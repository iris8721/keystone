//! Pseudonymous download records for leak investigation.
//!
//! One JSON line per manifest issue or blob download. Accounts appear as
//! HMAC-SHA256 pseudonyms under the watermark secret. Lines go through a
//! bounded channel to a single writer thread, so request handlers never
//! block on the file and records never interleave.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use chrono::Utc;
use hmac::{Hmac, Mac};
use keystone_core::fs::open_append_owner_only;
use same_file::Handle;
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroizing;

const QUEUE_DEPTH: usize = 1024;
const REOPEN_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Which payload route produced a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadRoute {
    /// `POST /payload`: manifest and wrapped key issued.
    ManifestIssued,
    /// `GET /payload/{product}/{version}`: sealed blob served.
    BlobServed,
}

#[derive(Serialize)]
struct DownloadRecord<'a> {
    #[serde(with = "keystone_core::wire::millis")]
    ts: chrono::DateTime<Utc>,
    account_pseudonym: String,
    product: &'a str,
    version: &'a str,
    build_id: &'a str,
    session_tag: &'a str,
    route: PayloadRoute,
}

/// Append-only JSONL download log, owner-only on every platform. Reopens the
/// path when the file behind it is rotated away, checked at most once per
/// second by file identity.
pub struct DownloadLog {
    tx: SyncSender<Vec<u8>>,
    secret: Zeroizing<[u8; 32]>,
}

impl DownloadLog {
    /// Open (creating) the log at `path` and start its writer thread.
    /// `pseudonym_secret` keys the account pseudonyms.
    pub fn open(path: &Path, pseudonym_secret: &[u8; 32]) -> io::Result<Self> {
        let log = OpenLog::open(path)?;
        let (tx, rx) = mpsc::sync_channel(QUEUE_DEPTH);
        let path = path.to_path_buf();
        std::thread::Builder::new()
            .name("keystone-download-log".into())
            .spawn(move || writer(path, log, rx))?;
        Ok(Self {
            tx,
            secret: Zeroizing::new(*pseudonym_secret),
        })
    }

    /// hex(HMAC-SHA256(secret, account)): stable per account, unlinkable
    /// without the secret.
    pub fn account_pseudonym(&self, account: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret[..])
            .expect("HMAC accepts any key length");
        mac.update(account.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Queue one record. Never blocks: when the writer is behind by more
    /// than the queue depth the record is dropped with a warning.
    pub fn record(
        &self,
        route: PayloadRoute,
        account: &str,
        product: &str,
        version: &str,
        build_id: &str,
        session_tag: &str,
    ) {
        let record = DownloadRecord {
            ts: Utc::now(),
            account_pseudonym: self.account_pseudonym(account),
            product,
            version,
            build_id,
            session_tag,
            route,
        };
        let mut line = match serde_json::to_vec(&record) {
            Ok(line) => line,
            Err(e) => {
                tracing::warn!("download record not serializable: {e}");
                return;
            }
        };
        line.push(b'\n');
        match self.tx.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => tracing::warn!("download log queue full; record dropped"),
            Err(TrySendError::Disconnected(_)) => {
                tracing::warn!("download log writer stopped; record dropped")
            }
        }
    }
}

impl std::fmt::Debug for DownloadLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadLog").finish_non_exhaustive()
    }
}

/// The log file plus the identity of what it has open.
struct OpenLog {
    file: File,
    identity: Handle,
}

impl OpenLog {
    fn open(path: &Path) -> io::Result<Self> {
        Self::wrap(open_append_owner_only(path)?)
    }

    fn wrap(file: File) -> io::Result<Self> {
        let identity = Handle::from_file(file.try_clone()?)?;
        Ok(Self { file, identity })
    }

    /// Whether `path` no longer names the open file.
    fn replaced(&self, path: &Path) -> bool {
        Handle::from_path(path).map_or(true, |on_disk| on_disk != self.identity)
    }
}

fn writer(path: PathBuf, mut log: OpenLog, rx: Receiver<Vec<u8>>) {
    let mut checked = Instant::now();
    for line in rx {
        if checked.elapsed() >= REOPEN_CHECK_INTERVAL {
            checked = Instant::now();
            if log.replaced(&path) {
                match OpenLog::open(&path) {
                    Ok(reopened) => log = reopened,
                    Err(e) => {
                        tracing::warn!(path = %path.display(), "download log reopen failed: {e}")
                    }
                }
            }
        }
        if let Err(e) = log.file.write_all(&line) {
            tracing::warn!(path = %path.display(), "download log write failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    fn temp_log() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("keystone-dl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("downloads.jsonl")
    }

    fn lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("every line is one whole record"))
            .collect()
    }

    async fn wait_for(path: &Path, count: usize) -> Vec<serde_json::Value> {
        for _ in 0..200 {
            let got = lines(path);
            if got.len() >= count {
                return got;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{} never reached {count} lines", path.display());
    }

    fn record(log: &DownloadLog, version: &str) {
        log.record(
            PayloadRoute::BlobServed,
            "dev",
            "dev-product",
            version,
            "build-1",
            "0011223344556677",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_records_stay_whole_lines() {
        let path = temp_log();
        let log = Arc::new(DownloadLog::open(&path, &[3u8; 32]).unwrap());
        let writers: Vec<_> = (0..8)
            .map(|t| {
                let log = log.clone();
                std::thread::spawn(move || {
                    for i in 0..50 {
                        record(&log, &format!("{t}.{i}"));
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().unwrap();
        }
        let got = wait_for(&path, 400).await;
        assert_eq!(got.len(), 400);
        let pseudonym = log.account_pseudonym("dev");
        assert!(
            got.iter()
                .all(|l| l["account_pseudonym"] == pseudonym.as_str())
        );
        assert_ne!(
            pseudonym,
            DownloadLog::open(&temp_log(), &[4u8; 32])
                .unwrap()
                .account_pseudonym("dev")
        );
    }

    #[tokio::test]
    async fn rotated_log_is_reopened() {
        let path = temp_log();
        let log = DownloadLog::open(&path, &[3u8; 32]).unwrap();
        record(&log, "1");
        wait_for(&path, 1).await;

        let rotated = path.with_extension("jsonl.1");
        std::fs::rename(&path, &rotated).unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        record(&log, "2");
        let fresh = wait_for(&path, 1).await;
        assert_eq!(fresh[0]["version"], "2");
        let old = lines(&rotated);
        assert_eq!(old.len(), 1);
        assert_eq!(old[0]["version"], "1");
    }

    #[tokio::test]
    async fn equal_length_replacement_is_detected() {
        let path = temp_log();
        let log = DownloadLog::open(&path, &[3u8; 32]).unwrap();
        record(&log, "1");
        wait_for(&path, 1).await;

        // Same byte length as the original, so only file identity tells them apart.
        let rotated = path.with_extension("jsonl.1");
        std::fs::rename(&path, &rotated).unwrap();
        std::fs::copy(&rotated, &path).unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        record(&log, "2");
        let fresh = wait_for(&path, 2).await;
        assert_eq!(fresh[1]["version"], "2");
        assert_eq!(lines(&rotated).len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn log_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_log();
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _log = DownloadLog::open(&path, &[3u8; 32]).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
