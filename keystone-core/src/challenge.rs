use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// A fresh nonce the verifier issues before an authorization exchange.
/// The response must echo it — this is what makes a captured response
/// worthless in a new session.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(with = "serde_big_array::BigArray")]
    pub nonce: [u8; 32],
    pub issued_at: DateTime<Utc>,
    /// Challenges expire fast — a stale challenge is a replay window.
    pub ttl: Duration,
}

impl Challenge {
    pub fn fresh(ttl: Duration) -> Self {
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        Self {
            nonce,
            issued_at: Utc::now(),
            ttl,
        }
    }

    /// Deterministic constructor for tests and for reconstructing a
    /// challenge received over the wire.
    pub fn from_parts(nonce: [u8; 32], issued_at: DateTime<Utc>, ttl: Duration) -> Self {
        Self {
            nonce,
            issued_at,
            ttl,
        }
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.issued_at + self.ttl
    }
}
