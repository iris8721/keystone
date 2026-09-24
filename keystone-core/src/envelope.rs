//! Signed, challenge-bound, scoped authorization responses.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::challenge::Challenge;
use crate::crypto::{self, DOMAIN_ENVELOPE};
use crate::error::{KeystoneError, Result};
use crate::issuers::TrustedIssuers;

/// A signed authorization response: bound to the requester's challenge,
/// scoped to a session, audience, and operation, and bounded in time.
/// Single use is enforced by the caller's [`crate::ConsumedSet`].
#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Issuer key that signed this envelope; covered by the signature.
    pub key_id: u8,
    /// Echo of the requester's challenge nonce.
    pub challenge: [u8; 32],
    /// Session the grant belongs to.
    pub session_id: Uuid,
    /// Who the grant is addressed to, e.g. [`crate::wire::AUDIENCE_CLIENT`].
    pub audience: String,
    /// What the grant authorizes, e.g. [`crate::wire::OP_HEARTBEAT`].
    pub operation: String,
    /// Server clock at issue.
    #[serde(with = "crate::wire::millis")]
    pub issued_at: DateTime<Utc>,
    /// First instant at which the grant is dead.
    #[serde(with = "crate::wire::millis")]
    pub expires_at: DateTime<Utc>,
    /// Operation-specific body, usually a JSON `wire` body.
    pub body: Vec<u8>,
    /// Ed25519 signature over [`Envelope::canonical_bytes`].
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 64],
}

/// The bindings a session-bound verifier requires of an envelope.
#[derive(Debug, Clone, Copy)]
pub struct Expectation<'a> {
    /// The challenge this requester minted for the request.
    pub challenge: &'a Challenge,
    /// The session the requester is acting in.
    pub session_id: &'a Uuid,
    /// The audience the requester is.
    pub audience: &'a str,
    /// The operation the requester asked for.
    pub operation: &'a str,
    /// The requester's server-aligned clock.
    pub now: DateTime<Utc>,
}

/// The bindings required of the exchange envelope, before the requester
/// has any server-aligned clock.
#[derive(Debug, Clone, Copy)]
pub struct BootstrapExpectation<'a> {
    /// The challenge this requester minted for the exchange.
    pub challenge: &'a Challenge,
    /// The session id read from the envelope body.
    pub session_id: &'a Uuid,
    /// The audience the requester is.
    pub audience: &'a str,
    /// The operation the requester asked for.
    pub operation: &'a str,
}

/// Everything the server needs to mint an envelope.
#[derive(Debug, Clone)]
pub struct IssueSpec {
    /// The requester's challenge nonce.
    pub challenge: [u8; 32],
    /// Session the grant belongs to.
    pub session_id: Uuid,
    /// Who the grant is addressed to.
    pub audience: String,
    /// What the grant authorizes.
    pub operation: String,
    /// Server clock at issue.
    pub issued_at: DateTime<Utc>,
    /// First instant at which the grant is dead.
    pub expires_at: DateTime<Utc>,
    /// Operation-specific body.
    pub body: Vec<u8>,
}

impl Envelope {
    /// How far in the future `issued_at` may sit relative to the
    /// verifier's clock.
    const MAX_FUTURE_SKEW: chrono::Duration = chrono::Duration::seconds(30);

    /// The signed bytes: domain, key id, then every field length-prefixed
    /// or fixed-width, timestamps at millisecond precision.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            DOMAIN_ENVELOPE.len()
                + 1
                + 32
                + 16
                + 8
                + self.audience.len()
                + self.operation.len()
                + 16
                + 4
                + self.body.len(),
        );
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

    /// Build and sign an envelope under the issuer's key id.
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

    /// Verify a session-bound envelope: trusted key, signature, challenge
    /// echo (`ChallengeMismatch`) and challenge age (`Stale`), scope, then
    /// `ClockSkew` for a future `issued_at` and `Expired` at or past
    /// `expires_at`, both judged at `expect.now`.
    pub fn verify(&self, issuers: &TrustedIssuers, expect: &Expectation<'_>) -> Result<()> {
        self.verify_bindings(
            issuers,
            expect.challenge,
            expect.session_id,
            expect.audience,
            expect.operation,
        )?;
        if self.issued_at > expect.now + Self::MAX_FUTURE_SKEW {
            return Err(KeystoneError::ClockSkew);
        }
        if expect.now >= self.expires_at {
            return Err(KeystoneError::Expired);
        }
        Ok(())
    }

    /// Verify the exchange envelope, which establishes the requester's
    /// view of server time. Runs every check of [`Envelope::verify`] except
    /// the future-skew check. With `rtt` the time since the challenge was
    /// minted, the response is at most `rtt` old on the server's clock, so
    /// it is `Expired` when `issued_at + rtt >= expires_at`; the returned
    /// drift is `issued_at + rtt / 2 - Utc::now()`.
    pub fn verify_bootstrap(
        &self,
        issuers: &TrustedIssuers,
        expect: &BootstrapExpectation<'_>,
    ) -> Result<chrono::Duration> {
        self.verify_bindings(
            issuers,
            expect.challenge,
            expect.session_id,
            expect.audience,
            expect.operation,
        )?;
        // The challenge check above bounds rtt by Challenge::TTL.
        let rtt = chrono::Duration::from_std(expect.challenge.minted.elapsed())
            .map_err(|_| KeystoneError::Stale)?;
        let latest_server_now = self
            .issued_at
            .checked_add_signed(rtt)
            .ok_or(KeystoneError::Expired)?;
        if latest_server_now >= self.expires_at {
            return Err(KeystoneError::Expired);
        }
        Ok(latest_server_now - rtt / 2 - Utc::now())
    }

    fn verify_bindings(
        &self,
        issuers: &TrustedIssuers,
        challenge: &Challenge,
        session_id: &Uuid,
        audience: &str,
        operation: &str,
    ) -> Result<()> {
        let key = issuers.key_for(self.key_id)?;
        crypto::verify(key, &self.canonical_bytes(), &self.signature)?;
        // Constant-time so a partial match leaks nothing about the nonce.
        if !bool::from(self.challenge.ct_eq(&challenge.nonce)) {
            return Err(KeystoneError::ChallengeMismatch);
        }
        if challenge.is_expired() {
            return Err(KeystoneError::Stale);
        }
        if !bool::from(self.session_id.as_bytes().ct_eq(session_id.as_bytes())) {
            return Err(KeystoneError::SessionMismatch);
        }
        if self.audience != audience {
            return Err(KeystoneError::AudienceMismatch {
                expected: audience.to_string(),
                actual: self.audience.clone(),
            });
        }
        if self.operation != operation {
            return Err(KeystoneError::OperationMismatch {
                expected: operation.to_string(),
                actual: self.operation.clone(),
            });
        }
        Ok(())
    }
}

/// Prints the body as a length: it carries session material.
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
            .finish_non_exhaustive()
    }
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}
