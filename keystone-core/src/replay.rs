//! Single-use tracking for nonces.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use chrono::{DateTime, Utc};

use crate::error::{KeystoneError, Result};

/// Nonces accepted so far, each remembered until the value it
/// authorized expires. An entry is live while `expires_at > now`; a
/// nonce whose value is already dead is refused rather than recorded,
/// so there is no instant at which a nonce is both evictable and
/// acceptable.
#[derive(Debug, Default)]
pub struct ConsumedSet {
    consumed: HashMap<[u8; 32], DateTime<Utc>>,
}

impl ConsumedSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check-and-mark in one step. Fails with [`KeystoneError::Stale`]
    /// when `expires_at <= now` and with [`KeystoneError::AlreadyConsumed`]
    /// when the nonce is held; otherwise records it until `expires_at`.
    pub fn consume(
        &mut self,
        nonce: [u8; 32],
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if expires_at <= now {
            return Err(KeystoneError::Stale);
        }
        match self.consumed.entry(nonce) {
            Entry::Occupied(_) => Err(KeystoneError::AlreadyConsumed),
            Entry::Vacant(slot) => {
                slot.insert(expires_at);
                Ok(())
            }
        }
    }

    /// Whether `nonce` is currently held.
    pub fn is_consumed(&self, nonce: &[u8; 32]) -> bool {
        self.consumed.contains_key(nonce)
    }

    /// Drop every entry with `expires_at <= now`; `consume` refuses those
    /// values anyway.
    pub fn evict_expired(&mut self, now: DateTime<Utc>) {
        self.consumed.retain(|_, exp| *exp > now);
    }

    /// Number of held nonces.
    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    /// True when no nonce is held.
    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }
}
