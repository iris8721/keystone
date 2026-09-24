//! Durable record of revoked issuer key ids.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use keystone_core::{BackendError, fs, revocations};
use parking_lot::Mutex;

/// Where revoked issuer key ids survive restarts. The server persists a
/// revocation here before applying it.
#[async_trait]
pub trait RevocationStore: Send + Sync {
    /// Every key id revoked so far.
    async fn load(&self) -> Result<BTreeSet<u8>, BackendError>;

    /// Add `key_id`; returns once the revocation is durable.
    async fn persist(&self, key_id: u8) -> Result<(), BackendError>;
}

/// JSON array of key ids in one file, e.g. `[1,3]`. A missing or empty file
/// is an empty set; writes replace the file atomically, owner-only on every
/// platform, and are durable before [`RevocationStore::persist`] returns.
#[derive(Debug)]
pub struct FileRevocationStore {
    path: PathBuf,
    write: tokio::sync::Mutex<()>,
}

impl FileRevocationStore {
    /// A store backed by `path`; nothing is read until [`RevocationStore::load`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            write: tokio::sync::Mutex::new(()),
        }
    }

    /// The backing file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn read_ids(path: &Path) -> Result<BTreeSet<u8>, BackendError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            revocations::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()).into())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(format!("{}: {e}", path.display()).into()),
    }
}

#[async_trait]
impl RevocationStore for FileRevocationStore {
    async fn load(&self) -> Result<BTreeSet<u8>, BackendError> {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || read_ids(&path)).await?
    }

    async fn persist(&self, key_id: u8) -> Result<(), BackendError> {
        let _guard = self.write.lock().await;
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut ids = read_ids(&path)?;
            if ids.insert(key_id) {
                fs::write_owner_only_atomic(&path, &revocations::serialize(&ids))
                    .map_err(|e| format!("{}: {e}", path.display()))?;
            }
            Ok(())
        })
        .await?
    }
}

/// In-process [`RevocationStore`] for tests and embedders that persist
/// elsewhere.
#[derive(Debug, Default)]
pub struct MemoryRevocations {
    ids: Mutex<BTreeSet<u8>>,
}

impl MemoryRevocations {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RevocationStore for MemoryRevocations {
    async fn load(&self) -> Result<BTreeSet<u8>, BackendError> {
        Ok(self.ids.lock().clone())
    }

    async fn persist(&self, key_id: u8) -> Result<(), BackendError> {
        self.ids.lock().insert(key_id);
        Ok(())
    }
}
