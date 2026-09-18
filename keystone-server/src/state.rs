//! Shared application state threaded into every handler.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration as StdDuration, Instant, SystemTime};

use chrono::{DateTime, Duration, Utc};
use keystone_core::{EntitlementSource, Issuer};

use crate::downloads::DownloadLog;
use crate::store::SessionStore;

/// Server-issued challenges awaiting consumption. Every nonce the
/// server mints is recorded here; exchange and attest must present one
/// that exists, is unexpired, and hasn't been spent — then it's gone.
/// This is what makes a captured challenge worthless to replay.
#[derive(Debug, Default)]
pub struct ChallengeBook {
    /// nonce → expiry.
    outstanding: RwLock<HashMap<[u8; 32], DateTime<Utc>>>,
}

impl ChallengeBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue(&self, nonce: [u8; 32], expires_at: DateTime<Utc>) {
        self.outstanding
            .write()
            .expect("challenge book poisoned")
            .insert(nonce, expires_at);
    }

    /// Find-and-remove in one step. Unknown, expired, and already-spent
    /// nonces all fail identically — no oracle for which case hit.
    pub fn consume(&self, nonce: &[u8; 32], now: DateTime<Utc>) -> keystone_core::Result<()> {
        let mut book = self.outstanding.write().expect("challenge book poisoned");
        match book.remove(nonce) {
            Some(expires_at) if now < expires_at => Ok(()),
            _ => Err(keystone_core::KeystoneError::ChallengeMismatch),
        }
    }

    /// Drop expired entries — they can never be accepted anyway.
    pub fn evict_expired(&self, now: DateTime<Utc>) {
        self.outstanding
            .write()
            .expect("challenge book poisoned")
            .retain(|_, exp| *exp > now);
    }
}

/// Everything a handler needs. Cloning shares the same issuer, store,
/// and entitlement backend — axum clones state per request.
#[derive(Clone)]
pub struct AppState {
    /// The signing key behind every envelope. Wrapped in Arc because
    /// Issuer is not Clone and must never be duplicated per-request.
    pub issuer: Arc<Issuer>,
    pub store: SessionStore,
    pub entitlements: Arc<dyn EntitlementSource>,
    pub challenges: Arc<ChallengeBook>,
    /// sha256 of KEYSTONE_ADMIN_TOKEN. Stored hashed so the raw token
    /// never sits in process memory beyond startup; `None` means
    /// /revoke is closed entirely.
    pub admin_token_hash: Option<[u8; 32]>,
    /// How long a minted challenge stays valid — a stale challenge is
    /// a replay window.
    pub challenge_ttl: Duration,
    /// Lease lifetime per grant/renewal. Short on purpose: a lease is
    /// the only thing keeping protected operations alive.
    pub lease_ttl: Duration,
    /// Bounded tolerance for transient failure. Fixed at first failure;
    /// retries never extend it.
    pub grace_period: Duration,
    /// Directory holding released payload blobs as
    /// `{product}-{version}.bin` (KEYSTONE_PAYLOAD_DIR). `None` means
    /// the payload routes are closed entirely — a server that cannot
    /// serve artifacts must say so (503), not improvise.
    pub payload_dir: Option<std::path::PathBuf>,
    /// Server-held secret the artifact keys derive from
    /// (KEYSTONE_PAYLOAD_SECRET / KEYSTONE_PAYLOAD_SECRET_FILE). The
    /// sealed blobs are useless without it; it never leaves the server.
    pub payload_secret: Option<[u8; 32]>,
    /// Pseudonymous download records (KEYSTONE_DOWNLOAD_LOG, default
    /// `downloads.jsonl` inside the payload dir; pseudonym secret is
    /// KEYSTONE_WATERMARK_SECRET, falling back to the payload secret).
    /// `None` means logging is disabled — downloads still serve, they
    /// just leave no trail.
    pub downloads: Option<DownloadLog>,
    /// HMAC key for per-request manifest `download_id` stamps
    /// (KEYSTONE_WATERMARK_SECRET, falling back to the payload
    /// secret). `None` leaves download_id empty — manifests still
    /// verify, they just aren't attributable to one download.
    pub watermark_secret: Option<[u8; 32]>,
    /// Sliding-window rate limits per route.
    pub rate_limits: RateLimits,
    pub rate_limiter: Arc<RateLimiter>,
    /// Plaintext-hash cache for sealed artifacts — see the type.
    pub artifact_hashes: Arc<ArtifactHashes>,
}

/// Per-route sliding-window limits. Configured once at startup; tests
/// shrink them to exercise the 429 path without a real burst.
#[derive(Debug, Clone, Copy)]
pub struct RateLimits {
    /// /exchange per source IP — argon2 makes each attempt expensive,
    /// but an unbounded flood still costs CPU per request.
    pub exchange_per_ip: u32,
    /// /exchange per account — credential stuffing against one account
    /// from rotating IPs must still hit a wall.
    pub exchange_per_account: u32,
    /// /challenge per source IP — challenges are cheap to mint, so the
    /// ceiling is generous; it exists to bound the book's growth.
    pub challenge_per_ip: u32,
    /// /revoke per source IP — admin-gated anyway; the limit keeps a
    /// token-guessing flood from being free.
    pub revoke_per_ip: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            exchange_per_ip: 10,
            exchange_per_account: 5,
            challenge_per_ip: 30,
            revoke_per_ip: 5,
        }
    }
}

/// Sliding-window rate limiter: one timestamp deque per key, hits
/// older than the window dropped on each check. In-memory only — a
/// restart resets the counters, which is fine: the window is a minute.
#[derive(Debug, Default)]
pub struct RateLimiter {
    hits: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    /// Window every limit slides over.
    const WINDOW: StdDuration = StdDuration::from_secs(60);
    /// Bound on tracked keys — a flood of unique IPs must not grow the
    /// map without limit. Past the cap, stale keys are pruned; if none
    /// are stale the request is denied rather than tracked.
    const MAX_KEYS: usize = 65_536;

    pub fn new() -> Self {
        Self::default()
    }

    /// Record a hit for `key`; `true` while the key is under `limit`
    /// hits in the trailing window.
    pub fn check(&self, key: &str, limit: u32) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().expect("rate limiter poisoned");
        if hits.len() >= Self::MAX_KEYS {
            let window = Self::WINDOW;
            hits.retain(|_, dq| dq.back().is_some_and(|t| now - *t < window));
            if hits.len() >= Self::MAX_KEYS {
                return false;
            }
        }
        let dq = hits.entry(key.to_string()).or_default();
        while dq.front().is_some_and(|t| now - *t >= Self::WINDOW) {
            dq.pop_front();
        }
        if dq.len() >= limit as usize {
            return false;
        }
        dq.push_back(now);
        true
    }

    /// The per-IP bucket key, namespaced by route so a burst on one
    /// endpoint can't burn another's budget. Requests without connect
    /// info (in-process test calls) share one bucket — they can't be
    /// told apart anyway.
    pub fn ip_key(route: &str, addr: Option<IpAddr>) -> String {
        match addr {
            Some(ip) => format!("{route}:ip:{ip}"),
            None => format!("{route}:ip:unknown"),
        }
    }
}

/// Plaintext sha256 of sealed artifacts, cached so manifest requests
/// don't pay a decrypt each time. `xtask seal` writes a `.sha256`
/// sidecar that short-circuits this entirely; the cache covers
/// artifacts sealed before sidecars existed. Keyed by path + mtime so
/// a re-sealed artifact can't serve a stale hash.
#[derive(Debug, Default)]
pub struct ArtifactHashes {
    cache: Mutex<HashMap<PathBuf, (SystemTime, [u8; 32])>>,
}

impl ArtifactHashes {
    pub fn new() -> Self {
        Self::default()
    }

    /// The cached hash for `path` if the file's mtime still matches.
    pub fn get(&self, path: &std::path::Path, mtime: SystemTime) -> Option<[u8; 32]> {
        self.cache
            .lock()
            .expect("artifact hash cache poisoned")
            .get(path)
            .filter(|(cached_mtime, _)| *cached_mtime == mtime)
            .map(|(_, hash)| *hash)
    }

    pub fn insert(&self, path: PathBuf, mtime: SystemTime, hash: [u8; 32]) {
        self.cache
            .lock()
            .expect("artifact hash cache poisoned")
            .insert(path, (mtime, hash));
    }
}
