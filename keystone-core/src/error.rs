//! The error taxonomy shared by every keystone check.

use thiserror::Error;

/// Every way an authorization check can fail. Variants stay specific so
/// the server can tell forgery from replay and the client can tell a
/// verdict from a transient failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KeystoneError {
    /// A signature did not verify under the named issuer key.
    #[error("signature verification failed")]
    InvalidSignature,

    /// The signing key id is unknown to the verifier or revoked.
    #[error("untrusted issuer key {key_id}")]
    UntrustedIssuer {
        /// The key id the rejected value named.
        key_id: u8,
    },

    /// A request MAC, AEAD tag, or key wrap failed to authenticate.
    #[error("MAC does not match")]
    InvalidMac,

    /// The response does not echo the challenge this requester issued.
    #[error("challenge does not match the outstanding request")]
    ChallengeMismatch,

    /// The nonce was already accepted once.
    #[error("response was already consumed")]
    AlreadyConsumed,

    /// The grant, lease, envelope, or blob is past its expiry.
    #[error("authorization expired")]
    Expired,

    /// The session was explicitly revoked.
    #[error("session is revoked")]
    Revoked,

    /// The server rejected the session's proof outright.
    #[error("session was rejected")]
    Rejected,

    /// The server does not know the session.
    #[error("unknown session")]
    UnknownSession,

    /// The envelope was minted for a different audience.
    #[error("audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch {
        /// The audience the verifier required.
        expected: String,
        /// The audience the envelope carried.
        actual: String,
    },

    /// The envelope authorizes a different operation.
    #[error("operation mismatch: expected {expected}, got {actual}")]
    OperationMismatch {
        /// The operation the verifier required.
        expected: String,
        /// The operation the envelope carried.
        actual: String,
    },

    /// The envelope is bound to a different session.
    #[error("session mismatch")]
    SessionMismatch,

    /// The handoff is unknown, spent, expired, or bound elsewhere.
    #[error("handoff is invalid")]
    HandoffInvalid,

    /// The grace deadline passed without a successful heartbeat.
    #[error("grace period exhausted")]
    GraceExhausted,

    /// The value arrived outside its freshness window.
    #[error("stale request or response")]
    Stale,

    /// A request field exceeds its wire cap; carries the field name.
    #[error("field {0} exceeds its length limit")]
    FieldTooLong(&'static str),

    /// Input failed to parse or violates a structural rule.
    #[error("malformed payload: {0}")]
    Malformed(String),

    /// A timestamp sits further in the future than the verifier tolerates.
    #[error("clock skew beyond tolerance")]
    ClockSkew,

    /// Reading or writing a file or stream failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// `std::result::Result` defaulting to [`KeystoneError`].
pub type Result<T, E = KeystoneError> = std::result::Result<T, E>;

/// Failure of a pluggable backend (entitlements, storage). Distinct from
/// a denial: callers answer it as an outage, not as a verdict.
pub type BackendError = Box<dyn std::error::Error + Send + Sync>;
