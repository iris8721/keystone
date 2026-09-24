//! Requester-minted challenges that make a captured response worthless
//! in any later exchange.

use std::time::{Duration, Instant};

/// A fresh nonce the requester sends and the signed response must echo.
/// Its lifetime runs on the monotonic clock, so wall-clock changes can
/// neither extend nor cut the window. Deliberately not serializable: a
/// challenge never leaves the process that minted it.
#[derive(Debug, Clone, Copy)]
pub struct Challenge {
    /// Random bytes the response must echo.
    pub nonce: [u8; 32],
    /// When this process minted the challenge.
    pub minted: Instant,
}

impl Challenge {
    /// How long a response to this challenge is accepted after minting.
    pub const TTL: Duration = Duration::from_secs(60);

    /// Mint a challenge with a random nonce, starting its window now.
    pub fn new() -> Self {
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        Self {
            nonce,
            minted: Instant::now(),
        }
    }

    /// True once [`Challenge::TTL`] has elapsed since minting.
    pub fn is_expired(&self) -> bool {
        self.minted.elapsed() >= Self::TTL
    }
}

impl Default for Challenge {
    fn default() -> Self {
        Self::new()
    }
}
