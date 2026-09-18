//! Pseudonymous download records — the deterrence layer's paper trail.
//!
//! Every successful manifest issue and blob download appends one JSONL
//! record. Accounts are recorded as HMAC-SHA256 pseudonyms under a
//! server-held secret: attributable when the secret is known, anonymous
//! when it isn't. Per DESIGN.md these records are supporting evidence
//! for a leak investigation, not proof.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;

/// Which payload route produced the record. Manifest-without-blob and
/// blob-without-manifest are different leak profiles, so the record
/// must say which half was served.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadRoute {
    /// POST /payload — the signed manifest was issued.
    ManifestIssued,
    /// GET /payload/{product}/{version} — the sealed blob was served.
    BlobServed,
}

/// One appended line. `account_pseudonym` is filled in by the log —
/// callers never see the secret.
#[derive(Serialize)]
struct DownloadRecord<'a> {
    ts: DateTime<Utc>,
    account_pseudonym: String,
    product: &'a str,
    version: &'a str,
    build_id: &'a str,
    /// Truncated sha256 of the session id — correlates records from
    /// one session without exposing the bearer id itself.
    session_tag: &'a str,
    route: PayloadRoute,
}

/// Append-only JSONL sink. `Clone` shares the same file handle and
/// secret — `AppState` clones per request.
#[derive(Clone)]
pub struct DownloadLog {
    inner: Arc<Inner>,
}

struct Inner {
    /// The open file under a mutex: one writer at a time, so a record
    /// is always a whole line even under concurrent downloads.
    file: Mutex<File>,
    /// HMAC key for account pseudonyms — the watermark secret, or the
    /// payload secret when no dedicated one is configured.
    secret: [u8; 32],
}

impl DownloadLog {
    /// Open (creating) the log for appending.
    pub fn open(path: &Path, secret: [u8; 32]) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            inner: Arc::new(Inner {
                file: Mutex::new(file),
                secret,
            }),
        })
    }

    /// hex(HMAC-SHA256(secret, account)) — stable per account under one
    /// secret, unlinkable without it.
    pub fn account_pseudonym(&self, account: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.inner.secret)
            .expect("HMAC accepts any key length");
        mac.update(account.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Append one record. No fsync: the log is supporting evidence, and
    /// a crash that loses the tail also loses the context the record
    /// would have described — not worth a syscall per download.
    pub fn record(
        &self,
        route: PayloadRoute,
        account: &str,
        product: &str,
        version: &str,
        build_id: &str,
        session_tag: &str,
    ) -> io::Result<()> {
        let record = DownloadRecord {
            ts: Utc::now(),
            account_pseudonym: self.account_pseudonym(account),
            product,
            version,
            build_id,
            session_tag,
            route,
        };
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        let mut file = self.inner.file.lock().expect("download log poisoned");
        file.write_all(&line)
    }
}
