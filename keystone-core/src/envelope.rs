use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::crypto::{self, DOMAIN_ENVELOPE};
use crate::error::{KeystoneError, Result};
use crate::issuers::TrustedIssuers;

/// A signed authorization response. Per the spec, every response must be
/// signed, fresh (challenge-bound), scoped (session + audience +
/// operation), and single-use (consumed on acceptance — enforced by the
/// replay cache, not this type).
#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Which issuer key signed this. Selects the verifying key from the
    /// verifier's `TrustedIssuers`; signed, so a response can't be
    /// re-pointed at a different key than the one that minted it.
    pub key_id: u8,
    /// Echoes the challenge the verifier issued. Replay of an old
    /// response fails here even with a valid signature.
    #[serde(with = "serde_big_array::BigArray")]
    pub challenge: [u8; 32],
    pub session_id: Uuid,
    /// What this response is for — e.g. "keystone-server". A response
    /// minted for one service must not verify for another.
    pub audience: String,
    /// The operation being authorized — e.g. "payload.download",
    /// "feature.aimbot". Binds the grant to the request.
    pub operation: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Opaque payload — grants, manifest, session material.
    pub body: Vec<u8>,
    /// Ed25519 signature over canonical_bytes().
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 64],
}

/// Fields the caller must prove when accepting an envelope. Anything not
/// asserted here is still checked (signature, expiry); these are the
/// bindings only the requester knows.
pub struct Expectation<'a> {
    pub challenge: &'a [u8; 32],
    pub session_id: &'a Uuid,
    pub audience: &'a str,
    pub operation: &'a str,
    /// Now, injected so tests control time.
    pub now: DateTime<Utc>,
}

/// Everything the server needs to mint an envelope. Grouped so the
/// signature can't silently drift from the fields it covers.
pub struct IssueSpec {
    pub challenge: [u8; 32],
    pub session_id: Uuid,
    pub audience: String,
    pub operation: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub body: Vec<u8>,
}

impl Envelope {
    /// Envelopes issued further than this in the future are rejected —
    /// a future-dated grant is either a forged timestamp or a broken
    /// clock, and neither should authorize anything.
    const MAX_FUTURE_SKEW: chrono::Duration = chrono::Duration::seconds(30);

    /// Canonical signed bytes. Explicit length-prefixed fields — no
    /// serialization ambiguity, no way for the wire format and the
    /// signed format to disagree.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN_ENVELOPE);
        buf.push(self.key_id);
        buf.extend_from_slice(&self.challenge);
        buf.extend_from_slice(self.session_id.as_bytes());
        push_str(&mut buf, &self.audience);
        push_str(&mut buf, &self.operation);
        buf.extend_from_slice(&self.issued_at.timestamp_millis().to_be_bytes());
        buf.extend_from_slice(&self.expires_at.timestamp_millis().to_be_bytes());
        buf.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.body);
        buf
    }

    /// Server-side: build and sign an envelope under the issuer's key id.
    pub fn issue(issuer: &crypto::Issuer, spec: IssueSpec) -> Self {
        let mut env = Self {
            key_id: issuer.key_id(),
            challenge: spec.challenge,
            session_id: spec.session_id,
            audience: spec.audience,
            operation: spec.operation,
            issued_at: spec.issued_at,
            expires_at: spec.expires_at,
            body: spec.body,
            signature: [0u8; 64],
        };
        env.signature = issuer.sign(&env.canonical_bytes());
        env
    }

    /// Client-side: resolve the signing key by id, verify the signature,
    /// then every binding. Order matters for the error taxonomy — key
    /// trust first (unknown or revoked issuer), then signature
    /// (forgery), then freshness, then scope, then expiry.
    pub fn verify(&self, issuers: &TrustedIssuers, expect: &Expectation<'_>) -> Result<()> {
        let key = issuers.key_for(self.key_id)?;
        crypto::verify(key, &self.canonical_bytes(), &self.signature)?;

        // Constant-time: the challenge is a secret-bound nonce, and a
        // byte-wise early-exit compare would leak how much matched.
        if !bool::from(self.challenge[..].ct_eq(&expect.challenge[..])) {
            return Err(KeystoneError::ChallengeMismatch);
        }
        if !bool::from(self.session_id.as_bytes()[..].ct_eq(&expect.session_id.as_bytes()[..])) {
            return Err(KeystoneError::SessionMismatch);
        }
        if self.audience != expect.audience {
            return Err(KeystoneError::AudienceMismatch {
                expected: expect.audience.to_string(),
                actual: self.audience.clone(),
            });
        }
        if self.operation != expect.operation {
            return Err(KeystoneError::OperationMismatch {
                expected: expect.operation.to_string(),
                actual: self.operation.clone(),
            });
        }
        if self.issued_at > expect.now + Self::MAX_FUTURE_SKEW {
            return Err(KeystoneError::ClockSkew);
        }
        if expect.now >= self.expires_at {
            return Err(KeystoneError::Expired);
        }
        Ok(())
    }
}

/// Manual Debug: `body` carries session material (grants, wrapped
/// keys), so it prints as a length, never bytes.
impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("key_id", &self.key_id)
            .field("challenge", &self.challenge)
            .field("session_id", &self.session_id)
            .field("audience", &self.audience)
            .field("operation", &self.operation)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("body", &format_args!("[{} bytes]", self.body.len()))
            .field("signature", &self.signature)
            .finish_non_exhaustive()
    }
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}
