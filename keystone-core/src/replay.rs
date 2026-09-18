use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::error::{KeystoneError, Result};

/// Single-use tracking for authorization responses. A response is
/// identified by its challenge nonce — since challenges are fresh per
/// request, a replayed response presents a nonce that's either unknown
/// (challenge mismatch, caught earlier) or already consumed (caught
/// here).
///
/// Entries carry the response's expiry so the cache can evict dead
/// entries instead of growing forever.
#[derive(Debug, Default)]
pub struct ConsumedSet {
    /// nonce → when the response that used it expires.
    consumed: HashMap<[u8; 32], DateTime<Utc>>,
}

impl ConsumedSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check-and-mark in one step. Returns AlreadyConsumed if this nonce
    /// was accepted before; otherwise records it with the response's
    /// expiry. Atomicity matters — checking then inserting separately
    /// would open a concurrent-replay race.
    pub fn consume(&mut self, nonce: [u8; 32], expires_at: DateTime<Utc>) -> Result<()> {
        if self.consumed.contains_key(&nonce) {
            return Err(KeystoneError::AlreadyConsumed);
        }
        self.consumed.insert(nonce, expires_at);
        Ok(())
    }

    pub fn is_consumed(&self, nonce: &[u8; 32]) -> bool {
        self.consumed.contains_key(nonce)
    }

    /// Drop entries whose responses are expired anyway — they can't be
    /// accepted again, so remembering them is waste.
    pub fn evict_expired(&mut self, now: DateTime<Utc>) {
        self.consumed.retain(|_, exp| *exp > now);
    }

    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }
}
