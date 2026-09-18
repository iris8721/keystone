//! File-backed entitlement source — the real local account backend.
//!
//! Accounts live in a JSON file (`KEYSTONE_ACCOUNTS`, default
//! `./accounts.json`) managed by `cargo xtask account`. The file is
//! re-read whenever its mtime changes, so `xtask` edits take effect
//! without a restart — correctness over caching, since a stat per call
//! is cheap next to an argon2 verify.
//!
//! Backend failures (missing or malformed file) surface as `Err`, which
//! the routes translate to a 503 — an outage, not a denial. Bad
//! credentials and missing grants are `Ok(None)`.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use async_trait::async_trait;
use chrono::Utc;
use keystone_core::{AccountFile, AccountIdentity, Entitlement, EntitlementSource, KeystoneError};

/// Local account backend: reads `KEYSTONE_ACCOUNTS`, reloads on mtime
/// change.
pub struct LocalAccounts {
    path: PathBuf,
    /// mtime of the file as last successfully loaded. Failed loads do
    /// not update it — a malformed file keeps erroring (and keeps being
    /// retried) until an operator fixes it, rather than being cached as
    /// a silent empty table.
    last_mtime: Mutex<Option<SystemTime>>,
    cache: Mutex<AccountFile>,
    /// Constant argon2 hash verified for unknown accounts so a
    /// missing-account lookup costs the same as a wrong-password one —
    /// otherwise response timing leaks which accounts exist.
    dummy_hash: String,
}

impl LocalAccounts {
    /// Open the backend at `path`. The initial load is attempted but
    /// not fatal: a missing or malformed file means every call errors
    /// (503) until the file is fixed — the server still starts, and no
    /// restart is needed once it is.
    pub fn open(path: PathBuf) -> Self {
        let salt = SaltString::generate(&mut OsRng);
        let dummy_hash = Argon2::default()
            .hash_password(b"keystone-timing-dummy", &salt)
            .expect("argon2 hashing the timing dummy must not fail")
            .to_string();
        let (cache, last_mtime) = match AccountFile::load(&path) {
            Ok(file) => (file, mtime(&path)),
            Err(e) => {
                tracing::warn!(path = %path.display(), "accounts file not loaded: {e} — backend will 503 until fixed");
                (AccountFile::default(), None)
            }
        };
        Self {
            path,
            last_mtime: Mutex::new(last_mtime),
            cache: Mutex::new(cache),
            dummy_hash,
        }
    }

    /// The current account table, reloading when the file's mtime has
    /// changed since the last successful load. Errors propagate — a
    /// missing or malformed file is a backend failure, never a silent
    /// "no accounts".
    fn current(&self) -> Result<AccountFile, KeystoneError> {
        let now_mtime = mtime(&self.path);
        {
            let last = self.last_mtime.lock().expect("accounts mtime poisoned");
            if *last == now_mtime && last.is_some() {
                return Ok(self.cache.lock().expect("accounts cache poisoned").clone());
            }
        }
        let file = AccountFile::load(&self.path)?;
        *self.cache.lock().expect("accounts cache poisoned") = file.clone();
        *self.last_mtime.lock().expect("accounts mtime poisoned") = now_mtime;
        Ok(file)
    }
}

/// The file's modification time, or `None` when it can't be stat'd —
/// which forces a load attempt so the real error surfaces from `load`.
fn mtime(path: &PathBuf) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

#[async_trait]
impl EntitlementSource for LocalAccounts {
    async fn authenticate(
        &self,
        account: &str,
        secret: &str,
    ) -> Result<Option<AccountIdentity>, KeystoneError> {
        let file = self.current()?;
        let record = file.accounts.iter().find(|a| a.name == account);
        // Unknown account → verify against the dummy hash anyway so the
        // argon2 cost is paid either way and timing stays uniform.
        let stored = record
            .map(|a| a.secret_hash.as_str())
            .unwrap_or(&self.dummy_hash);
        let parsed = PasswordHash::new(stored)
            .map_err(|e| KeystoneError::Malformed(format!("stored hash corrupt: {e}")))?;
        let ok = Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok();
        if ok && record.is_some() {
            Ok(Some(AccountIdentity {
                account: account.to_string(),
            }))
        } else {
            // Bad credentials are a denial, not a backend failure.
            Ok(None)
        }
    }

    async fn entitlement(
        &self,
        account: &str,
        product: &str,
    ) -> Result<Option<Entitlement>, KeystoneError> {
        let file = self.current()?;
        let now = Utc::now();
        Ok(file
            .accounts
            .iter()
            .find(|a| a.name == account)
            .and_then(|a| a.entitlements.iter().find(|g| g.product == product))
            // An expired grant authorizes nothing — report it the same
            // as no grant so the answer can't distinguish the two.
            .filter(|g| now < g.expires_at)
            .map(|g| Entitlement {
                account: account.to_string(),
                product: g.product.clone(),
                expires_at: g.expires_at,
                features: g.features.clone(),
            }))
    }

    /// The account's pinned client-cert fingerprint, decoded from hex.
    /// `Some` means /exchange must see exactly this cert (CN = account
    /// name) at the TLS layer; `None` means any CA-issued cert
    /// authenticates the install.
    async fn cert_sha256(&self, account: &str) -> Result<Option<[u8; 32]>, KeystoneError> {
        let file = self.current()?;
        let Some(hex_hash) = file
            .accounts
            .iter()
            .find(|a| a.name == account)
            .and_then(|a| a.cert_sha256.as_deref())
        else {
            return Ok(None);
        };
        let bytes = hex::decode(hex_hash).map_err(|e| {
            KeystoneError::Malformed(format!("cert_sha256 for {account} is not hex: {e}"))
        })?;
        let hash: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            KeystoneError::Malformed(format!(
                "cert_sha256 for {account} is {} bytes, expected 32",
                bytes.len()
            ))
        })?;
        Ok(Some(hash))
    }
}
