//! Encrypted client→application handoff (DESIGN.md step 5).
//!
//! The client seals the minimal session material into a blob and hands
//! it to the application it launches; the app opens it and attests
//! independently. The blob is worthless without the handoff key, which
//! travels out-of-band through the launch channel (env var, argv,
//! shared memory — transport is the launcher's problem, not ours).
//!
//! Three bindings, each enforced by a different mechanism:
//!
//! - **Integrity** — XChaCha20-Poly1305 AEAD tag over the ciphertext.
//! - **Recipient** — `process_id` is mixed into the HKDF info, so a
//!   blob sealed for one process identity cannot be opened under
//!   another even by someone holding the key. This is a name-level
//!   binding only: it binds the blob to a *claimed* identity string,
//!   not to a verified process — the OS never vouches for it.
//! - **Freshness** — `issued_at`/`ttl` are checked on open; both are
//!   bound into the AEAD's associated data so they can't be rewritten
//!   to extend the window.

use std::fmt;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use chrono::{DateTime, Duration, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::{KeystoneError, Result};
use crate::lease::Lease;

/// HKDF domain for the handoff AEAD key. Namespaced like every other
/// derived value so a key stretched for one purpose is never valid
/// for another.
const DOMAIN_HANDOFF: &[u8] = b"keystone.handoff.v1";

/// The sealed blob the client hands to the application. Everything
/// sensitive is inside `ciphertext`; the cleartext fields are the
/// nonce and the freshness window, both authenticated via AAD.
#[derive(Clone, Serialize, Deserialize)]
pub struct Handoff {
    /// XChaCha20 nonce — also the HKDF salt, so the derived key is
    /// unique per blob even if the handoff key were ever reused.
    #[serde(with = "serde_big_array::BigArray")]
    pub nonce: [u8; 24],
    pub issued_at: DateTime<Utc>,
    /// How long the blob may sit before the app opens it. Short —
    /// a handoff is a launch-time event, not a stored credential.
    pub ttl: Duration,
    pub ciphertext: Vec<u8>,
}

/// The plaintext inside the blob: exactly what the app needs to
/// attest — session id, session key, current lease, and the pinned
/// issuer key — and nothing else. No credentials, no logs.
#[derive(Clone, Serialize, Deserialize)]
pub struct HandoffPayload {
    pub session_id: Uuid,
    #[serde(with = "serde_big_array::BigArray")]
    pub session_key: [u8; 32],
    pub lease: Lease,
    /// The issuer verifying key the app must pin. Carried in the blob
    /// so the sealed material is self-contained — the app never has
    /// to trust a key the client passes unauthenticated.
    #[serde(with = "serde_big_array::BigArray")]
    pub server_pubkey: [u8; 32],
}

/// Stretch the launch-channel secret into the AEAD key. `process_id`
/// in the info string is the recipient binding: opening under a
/// different identity derives a different key and the tag fails.
fn aead_key(handoff_key: &[u8; 32], nonce: &[u8; 24], process_id: &str) -> XChaCha20Poly1305 {
    let hk = Hkdf::<Sha256>::new(Some(nonce), handoff_key);
    let mut key = [0u8; 32];
    let mut info = Vec::with_capacity(DOMAIN_HANDOFF.len() + process_id.len());
    info.extend_from_slice(DOMAIN_HANDOFF);
    info.extend_from_slice(process_id.as_bytes());
    hk.expand(&info, &mut key)
        .expect("32 bytes is within HKDF-SHA256 output limit");
    XChaCha20Poly1305::new((&key).into())
}

/// Associated data: the freshness window. Without this an attacker
/// holding a captured blob could rewrite `issued_at`/`ttl` and open
/// it long after the intended window — the tag now covers them.
fn aad(issued_at: DateTime<Utc>, ttl: Duration) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16);
    aad.extend_from_slice(&issued_at.timestamp_millis().to_be_bytes());
    aad.extend_from_slice(&ttl.num_milliseconds().to_be_bytes());
    aad
}

impl Handoff {
    /// Blobs issued further than this in the future are rejected —
    /// same posture as `Envelope`: a future-dated grant is a forged
    /// timestamp or a broken clock, and neither should open.
    const MAX_FUTURE_SKEW: Duration = Duration::seconds(30);

    /// Upper bound on a sealable ttl — a handoff is a launch-time
    /// event, so anything past an hour is a caller bug. The client
    /// clamps to 5 minutes; this is defense in depth at the layer that
    /// actually mints the blob.
    const MAX_TTL: Duration = Duration::hours(1);

    /// Seal `payload` for the process identified by `process_id`.
    ///
    /// `handoff_key` is fresh randomness the caller generated and will
    /// deliver to the child process through the launch channel; the
    /// blob alone is useless without it.
    pub fn seal(
        handoff_key: &[u8; 32],
        payload: &HandoffPayload,
        process_id: &str,
        ttl: Duration,
    ) -> Result<Self> {
        if ttl < Duration::zero() || ttl > Self::MAX_TTL {
            return Err(KeystoneError::Malformed(format!(
                "handoff ttl {ttl} outside 0..={}",
                Self::MAX_TTL
            )));
        }
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
        let issued_at = Utc::now();
        let plaintext = serde_json::to_vec(payload)
            .map_err(|e| KeystoneError::Malformed(format!("handoff payload: {e}")))?;
        let ciphertext = aead_key(handoff_key, &nonce.into(), process_id)
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad(issued_at, ttl),
                },
            )
            .map_err(|_| KeystoneError::Malformed("handoff seal failed".into()))?;
        Ok(Self {
            nonce: nonce.into(),
            issued_at,
            ttl,
            ciphertext,
        })
    }

    /// Open the blob as `process_id` at `now`.
    ///
    /// Decrypt first, freshness second: until the tag verifies, the
    /// timestamps are unauthenticated input and must not produce a
    /// verdict. A wrong key, wrong recipient, or tampered byte all
    /// surface as `InvalidMac`; only an intact blob can be `Expired`
    /// or `ClockSkew`.
    pub fn open(
        &self,
        handoff_key: &[u8; 32],
        process_id: &str,
        now: DateTime<Utc>,
    ) -> Result<HandoffPayload> {
        let plaintext = aead_key(handoff_key, &self.nonce, process_id)
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad(self.issued_at, self.ttl),
                },
            )
            .map_err(|_| KeystoneError::InvalidMac)?;
        if self.issued_at > now + Self::MAX_FUTURE_SKEW {
            return Err(KeystoneError::ClockSkew);
        }
        let deadline = self
            .issued_at
            .checked_add_signed(self.ttl)
            .ok_or(KeystoneError::Expired)?;
        if now >= deadline {
            return Err(KeystoneError::Expired);
        }
        serde_json::from_slice(&plaintext)
            .map_err(|e| KeystoneError::Malformed(format!("handoff payload: {e}")))
    }
}

/// Manual Debug: the ciphertext is opaque to logs — print its length,
/// never its bytes.
impl fmt::Debug for Handoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handoff")
            .field("nonce", &self.nonce)
            .field("issued_at", &self.issued_at)
            .field("ttl", &self.ttl)
            .field("ciphertext", &format_args!("[{} bytes]", self.ciphertext.len()))
            .finish_non_exhaustive()
    }
}

/// Manual Debug: `session_key` is the crown jewel the blob exists to
/// protect — it must never reach a log line.
impl fmt::Debug for HandoffPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandoffPayload")
            .field("session_id", &self.session_id)
            .field("session_key", &"[redacted]")
            .field("lease", &self.lease)
            .field("server_pubkey", &self.server_pubkey)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];
    const PROCESS: &str = "game.exe";

    fn payload() -> HandoffPayload {
        HandoffPayload {
            session_id: Uuid::nil(),
            session_key: [0xAB; 32],
            lease: Lease {
                session_id: Uuid::nil(),
                granted_at: Utc::now(),
                expires_at: Utc::now() + Duration::seconds(300),
                grace_period: Duration::seconds(60),
            },
            server_pubkey: [0x77; 32],
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let blob = Handoff::seal(&KEY, &payload(), PROCESS, Duration::seconds(60)).unwrap();
        let opened = blob.open(&KEY, PROCESS, Utc::now()).unwrap();
        assert_eq!(opened.session_id, Uuid::nil());
        assert_eq!(opened.session_key, [0xAB; 32]);
        assert_eq!(opened.server_pubkey, [0x77; 32]);
    }

    #[test]
    fn wrong_process_id_fails() {
        let blob = Handoff::seal(&KEY, &payload(), PROCESS, Duration::seconds(60)).unwrap();
        assert!(matches!(
            blob.open(&KEY, "other.exe", Utc::now()),
            Err(KeystoneError::InvalidMac)
        ));
    }

    #[test]
    fn wrong_key_fails() {
        let blob = Handoff::seal(&KEY, &payload(), PROCESS, Duration::seconds(60)).unwrap();
        assert!(matches!(
            blob.open(&[0x99; 32], PROCESS, Utc::now()),
            Err(KeystoneError::InvalidMac)
        ));
    }

    #[test]
    fn expired_blob_fails() {
        let blob = Handoff::seal(&KEY, &payload(), PROCESS, Duration::seconds(60)).unwrap();
        let later = blob.issued_at + Duration::seconds(61);
        assert!(matches!(
            blob.open(&KEY, PROCESS, later),
            Err(KeystoneError::Expired)
        ));
    }

    #[test]
    fn future_issued_blob_fails() {
        let blob = Handoff::seal(&KEY, &payload(), PROCESS, Duration::seconds(60)).unwrap();
        let past = blob.issued_at - Duration::seconds(31);
        assert!(matches!(
            blob.open(&KEY, PROCESS, past),
            Err(KeystoneError::ClockSkew)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut blob = Handoff::seal(&KEY, &payload(), PROCESS, Duration::seconds(60)).unwrap();
        blob.ciphertext[0] ^= 1;
        assert!(matches!(
            blob.open(&KEY, PROCESS, Utc::now()),
            Err(KeystoneError::InvalidMac)
        ));
    }

    #[test]
    fn tampered_ttl_fails() {
        // issued_at/ttl are AAD — extending the window breaks the tag.
        let mut blob = Handoff::seal(&KEY, &payload(), PROCESS, Duration::seconds(60)).unwrap();
        blob.ttl = Duration::days(1);
        assert!(matches!(
            blob.open(&KEY, PROCESS, Utc::now()),
            Err(KeystoneError::InvalidMac)
        ));
    }

    #[test]
    fn seal_rejects_absurd_ttl() {
        // A handoff is a launch-time event — anything past MAX_TTL is a
        // caller bug, and a negative ttl is nonsense.
        assert!(matches!(
            Handoff::seal(&KEY, &payload(), PROCESS, Duration::hours(2)),
            Err(KeystoneError::Malformed(_))
        ));
        assert!(matches!(
            Handoff::seal(&KEY, &payload(), PROCESS, Duration::seconds(-1)),
            Err(KeystoneError::Malformed(_))
        ));
        // The boundary itself still seals.
        Handoff::seal(&KEY, &payload(), PROCESS, Handoff::MAX_TTL).unwrap();
    }

    #[test]
    fn overflowing_ttl_expires_not_panics() {
        // issued_at + ttl beyond DateTime's range must be Expired, not
        // a panic — a hostile blob can't crash the opener. seal()
        // refuses this ttl, so the blob is forged by hand: the tag is
        // still valid because the AAD covers the same absurd ttl.
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
        let issued_at = Utc::now();
        let plaintext = serde_json::to_vec(&payload()).unwrap();
        let ciphertext = aead_key(&KEY, &nonce.into(), PROCESS)
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad(issued_at, Duration::MAX),
                },
            )
            .unwrap();
        let blob = Handoff {
            nonce: nonce.into(),
            issued_at,
            ttl: Duration::MAX,
            ciphertext,
        };
        assert!(matches!(
            blob.open(&KEY, PROCESS, Utc::now()),
            Err(KeystoneError::Expired)
        ));
    }
}

