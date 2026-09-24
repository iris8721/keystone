//! Sliding-window rate limiting.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

/// Rate limiter seam. A key is any string the routes derive (route plus IP
/// prefix, session, or account); `limit` hits are allowed per `window`.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Charge one hit to `key`; false (and no charge) when the key already
    /// has `limit` hits inside `window`.
    async fn check(&self, key: &str, limit: u32, window: Duration) -> bool;

    /// Whether `key` is under `limit` inside `window`, without charging it.
    async fn peek(&self, key: &str, limit: u32, window: Duration) -> bool;

    /// Return the most recent hit charged to `key`, so a reservation taken
    /// with [`RateLimiter::check`] can be released once it proved unneeded.
    async fn refund(&self, key: &str);

    /// Drop state that can no longer deny anything at `now`.
    async fn evict(&self, now: Instant);
}

struct Bucket {
    hits: VecDeque<Instant>,
    window: Duration,
    last_used: Instant,
}

impl Bucket {
    fn prune(&mut self, now: Instant) {
        while self
            .hits
            .front()
            .is_some_and(|t| now.duration_since(*t) >= self.window)
        {
            self.hits.pop_front();
        }
    }

    fn is_stale(&self, now: Instant) -> bool {
        self.hits
            .back()
            .is_none_or(|t| now.duration_since(*t) >= self.window)
    }
}

/// In-process [`RateLimiter`]. Keys are stored as sha256 digests. When the
/// map is full, stale buckets go first, then the least recently used ones;
/// an existing key is never denied because of map pressure.
pub struct MemoryLimiter {
    buckets: Mutex<HashMap<[u8; 32], Bucket>>,
    capacity: usize,
}

impl MemoryLimiter {
    /// Default bound on tracked keys.
    pub const DEFAULT_CAPACITY: usize = 65_536;

    /// A limiter tracking at most [`Self::DEFAULT_CAPACITY`] keys.
    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    /// A limiter tracking at most `capacity` keys (minimum 1).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    fn lock(&self) -> parking_lot::MutexGuard<'_, HashMap<[u8; 32], Bucket>> {
        self.buckets.lock()
    }

    fn make_room(&self, buckets: &mut HashMap<[u8; 32], Bucket>, now: Instant) {
        buckets.retain(|_, b| !b.is_stale(now));
        if buckets.len() < self.capacity {
            return;
        }
        // Evict LRU keys in batches so a flood of new keys pays for the scan once per batch.
        let batch = (self.capacity / 8).max(1);
        let mut by_age: Vec<(Instant, [u8; 32])> =
            buckets.iter().map(|(k, b)| (b.last_used, *k)).collect();
        let cut = batch.min(by_age.len()) - 1;
        by_age.select_nth_unstable_by_key(cut, |(t, _)| *t);
        for (_, key) in &by_age[..=cut] {
            buckets.remove(key);
        }
    }
}

impl Default for MemoryLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MemoryLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryLimiter")
            .field("keys", &self.lock().len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

fn digest(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

#[async_trait]
impl RateLimiter for MemoryLimiter {
    async fn check(&self, key: &str, limit: u32, window: Duration) -> bool {
        let now = Instant::now();
        let id = digest(key);
        let mut buckets = self.lock();
        if !buckets.contains_key(&id) && buckets.len() >= self.capacity {
            self.make_room(&mut buckets, now);
        }
        let bucket = buckets.entry(id).or_insert_with(|| Bucket {
            hits: VecDeque::new(),
            window,
            last_used: now,
        });
        bucket.window = window;
        bucket.last_used = now;
        bucket.prune(now);
        if bucket.hits.len() >= limit as usize {
            return false;
        }
        bucket.hits.push_back(now);
        true
    }

    async fn peek(&self, key: &str, limit: u32, window: Duration) -> bool {
        let now = Instant::now();
        let buckets = self.lock();
        let Some(bucket) = buckets.get(&digest(key)) else {
            return limit > 0;
        };
        let live = bucket
            .hits
            .iter()
            .filter(|t| now.duration_since(**t) < window)
            .count();
        live < limit as usize
    }

    async fn refund(&self, key: &str) {
        if let Some(bucket) = self.lock().get_mut(&digest(key)) {
            bucket.hits.pop_back();
        }
    }

    async fn evict(&self, now: Instant) {
        self.lock().retain(|_, b| !b.is_stale(now));
    }
}
