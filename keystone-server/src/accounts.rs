//! File-backed entitlement source and the shared argon2 verifier.
//!
//! Backend failures (missing or malformed file) are `Err`, which the
//! routes answer with 503; bad credentials and missing grants are
//! `Ok(None)`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use async_trait::async_trait;
use chrono::Utc;
use keystone_core::{AccountFile, AccountIdentity, BackendError, Entitlement, EntitlementSource};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

/// Runs argon2 verification off the async executor, at most one per
/// available core at a time, and pays the full cost for unknown accounts
/// so timing does not reveal which accounts exist.
pub(crate) struct SecretVerifier {
    permits: Arc<Semaphore>,
    dummy_hash: Arc<str>,
}

impl SecretVerifier {
    pub(crate) fn new() -> Self {
        let parallelism = std::thread::available_parallelism().map_or(1, |n| n.get());
        Self {
            permits: Arc::new(Semaphore::new(parallelism)),
            dummy_hash: hash_secret("keystone-timing-dummy").into(),
        }
    }

    /// Whether `secret` matches `stored`; always false when `stored` is None.
    pub(crate) async fn verify(
        &self,
        stored: Option<String>,
        secret: &str,
    ) -> Result<bool, BackendError> {
        let _permit = self.permits.clone().acquire_owned().await?;
        let known = stored.is_some();
        let hash = stored.unwrap_or_else(|| self.dummy_hash.to_string());
        let secret = Zeroizing::new(secret.to_owned());
        let matched = tokio::task::spawn_blocking(move || {
            let parsed = PasswordHash::new(&hash)
                .map_err(|e| BackendError::from(format!("stored hash corrupt: {e}")))?;
            Ok::<_, BackendError>(
                Argon2::default()
                    .verify_password(secret.as_bytes(), &parsed)
                    .is_ok(),
            )
        })
        .await??;
        Ok(matched && known)
    }
}

/// Argon2id PHC string for `secret` under a fresh salt.
pub(crate) fn hash_secret(secret: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .expect("argon2 hashing with default parameters cannot fail")
        .to_string()
}

const RECHECK_INTERVAL: Duration = Duration::from_secs(1);

type Stamp = (Option<SystemTime>, u64);

/// One published view of the accounts file.
struct Snapshot {
    loaded: Result<Arc<AccountFile>, Arc<str>>,
    stamp: Option<Stamp>,
    checked_at: Instant,
}

/// Local account backend over the accounts file (`KEYSTONE_ACCOUNTS`).
/// The parsed file is published through an atomic pointer swap; readers
/// never wait on a lock. The path is stat'd at most once per second, off
/// the executor, and edits are picked up without a restart.
pub struct LocalAccounts {
    path: Arc<Path>,
    verifier: SecretVerifier,
    snapshot: ArcSwap<Snapshot>,
    refreshing: AtomicBool,
}

impl LocalAccounts {
    /// Open the backend at `path`. A missing or malformed file is not fatal
    /// here: every call errors (503) until the file is fixed.
    pub fn open(path: PathBuf) -> Self {
        let snapshot = load(&path);
        if let Err(e) = &snapshot.loaded {
            tracing::warn!(path = %path.display(), "accounts file not loaded: {e}");
        }
        Self {
            path: path.into(),
            verifier: SecretVerifier::new(),
            snapshot: ArcSwap::from_pointee(snapshot),
            refreshing: AtomicBool::new(false),
        }
    }

    async fn current(&self) -> Result<Arc<AccountFile>, BackendError> {
        let mut snapshot = self.snapshot.load_full();
        // One caller refreshes a stale view; the rest keep using the old one.
        if snapshot.checked_at.elapsed() >= RECHECK_INTERVAL
            && self
                .refreshing
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            let path = self.path.clone();
            let previous = snapshot.clone();
            let refreshed = tokio::task::spawn_blocking(move || refresh(&path, &previous)).await;
            self.refreshing.store(false, Ordering::Release);
            snapshot = Arc::new(refreshed?);
            self.snapshot.store(snapshot.clone());
        }
        snapshot
            .loaded
            .clone()
            .map_err(|e| BackendError::from(e.to_string()))
    }
}

fn stamp(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok(), meta.len()))
}

fn load(path: &Path) -> Snapshot {
    let stamp = stamp(path);
    let loaded = AccountFile::load(path)
        .map(Arc::new)
        .map_err(|e| Arc::from(e.to_string()));
    Snapshot {
        loaded,
        stamp,
        checked_at: Instant::now(),
    }
}

/// Reload when the file changed or the last load failed; otherwise keep the
/// parsed file and only move the check time.
fn refresh(path: &Path, previous: &Snapshot) -> Snapshot {
    let now_stamp = stamp(path);
    if previous.loaded.is_err() || now_stamp.is_none() || now_stamp != previous.stamp {
        return load(path);
    }
    Snapshot {
        loaded: previous.loaded.clone(),
        stamp: previous.stamp,
        checked_at: Instant::now(),
    }
}

#[async_trait]
impl EntitlementSource for LocalAccounts {
    async fn authenticate(
        &self,
        account: &str,
        secret: &str,
    ) -> Result<Option<AccountIdentity>, BackendError> {
        let file = self.current().await?;
        let stored = file
            .accounts
            .iter()
            .find(|a| a.name == account)
            .map(|a| a.secret_hash.clone());
        Ok(self
            .verifier
            .verify(stored, secret)
            .await?
            .then(|| AccountIdentity {
                account: account.to_string(),
            }))
    }

    async fn entitlement(
        &self,
        account: &str,
        product: &str,
    ) -> Result<Option<Entitlement>, BackendError> {
        let file = self.current().await?;
        let now = Utc::now();
        Ok(file
            .accounts
            .iter()
            .find(|a| a.name == account)
            .and_then(|a| a.entitlements.iter().find(|g| g.product == product))
            .filter(|g| now < g.expires_at)
            .map(|g| Entitlement {
                account: account.to_string(),
                product: g.product.clone(),
                expires_at: g.expires_at,
                features: g.features.clone(),
            }))
    }

    async fn cert_sha256(&self, account: &str) -> Result<Option<[u8; 32]>, BackendError> {
        let file = self.current().await?;
        let Some(hex_hash) = file
            .accounts
            .iter()
            .find(|a| a.name == account)
            .and_then(|a| a.cert_sha256.as_deref())
        else {
            return Ok(None);
        };
        let hash = hex::decode(hex_hash)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| BackendError::from("cert_sha256 is not 64 hex characters"))?;
        Ok(Some(hash))
    }
}
