//! Local account file — the schema keystone-server reads and xtask
//! writes.
//!
//! Keystone owns accounts directly; there is no forum dependency. The
//! file lives at `KEYSTONE_ACCOUNTS` (default `./accounts.json`) and
//! looks like:
//!
//! ```json
//! {"accounts":[{"name":"dev","secret_hash":"<argon2 PHC>",
//!   "entitlements":[{"product":"x","expires_at":"<rfc3339>",
//!   "features":["a","b"]}],"cert_sha256":"<optional hex>"}]}
//! ```
//!
//! `cert_sha256` binds the account to a specific client certificate:
//! when present, the TLS client cert's DER sha256 must match and its CN
//! must equal the account name. Absent, any CA-issued client cert
//! authenticates the install.
//!
//! The schema lives in keystone-core — not the server — so xtask writes
//! exactly what the server reads; two copies would drift.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::KeystoneError;

/// The parsed contents of the accounts file.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AccountFile {
    pub accounts: Vec<AccountRecord>,
}

/// One account: credentials, product grants, optional cert binding.
#[derive(Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub name: String,
    /// Argon2 PHC string — never the plaintext secret.
    pub secret_hash: String,
    #[serde(default)]
    pub entitlements: Vec<AccountGrant>,
    /// Optional sha256 of the client certificate's DER. When set, mTLS
    /// must present exactly this cert (CN = `name`); when absent, any
    /// CA-issued cert authenticates the install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_sha256: Option<String>,
}

/// A product grant as stored in the file — the account name is implied
/// by the record holding it, so it isn't repeated per grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountGrant {
    pub product: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub features: Vec<String>,
}

impl AccountFile {
    /// Read and parse the accounts file. A missing file and a malformed
    /// file are both backend failures — the caller decides whether that
    /// means refusing to start or answering 503.
    pub fn load(path: &Path) -> Result<Self, KeystoneError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            KeystoneError::Malformed(format!("accounts file {}: {e}", path.display()))
        })?;
        serde_json::from_str(&text)
            .map_err(|e| KeystoneError::Malformed(format!("accounts file {}: {e}", path.display())))
    }

    /// Atomically replace the accounts file: write a uniquely-named
    /// sibling temp file, fsync it, then rename over the target. A
    /// crash mid-write leaves either the old file or the new one —
    /// never a truncated half-JSON the server would read as "no
    /// accounts". The temp name carries pid + random suffix so two
    /// concurrent saves can't collide on a fixed `.tmp`.
    pub fn save(&self, path: &Path) -> Result<(), KeystoneError> {
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| KeystoneError::Malformed(format!("serializing accounts file: {e}")))?;
        let mut tmp_name = path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        tmp_name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        let tmp: PathBuf = path.with_file_name(tmp_name);

        let write_result = (|| -> std::io::Result<()> {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(text.as_bytes())?;
            // Flush to disk before the rename so a crash can't leave a
            // renamed-but-empty target.
            file.sync_all()
        })();
        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&tmp);
            return Err(KeystoneError::Malformed(format!(
                "writing {}: {e}",
                tmp.display()
            )));
        }

        std::fs::rename(&tmp, path)
            .map_err(|e| KeystoneError::Malformed(format!("replacing {}: {e}", path.display())))?;

        // Fsync the directory so the rename itself survives a crash.
        // Best-effort: Windows can't open a directory as a File, so
        // this is a no-op there — the rename is still atomic, just not
        // guaranteed durable.
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
            && let Ok(dir) = std::fs::File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

/// Manual Debug: `secret_hash` is a password verifier — it must never
/// reach a log line.
impl fmt::Debug for AccountRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountRecord")
            .field("name", &self.name)
            .field("secret_hash", &"[redacted]")
            .field("entitlements", &self.entitlements)
            .field("cert_sha256", &self.cert_sha256)
            .finish_non_exhaustive()
    }
}

/// Manual Debug so the redaction above can't be bypassed by a future
/// field added here.
impl fmt::Debug for AccountFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountFile")
            .field("accounts", &self.accounts)
            .finish_non_exhaustive()
    }
}
