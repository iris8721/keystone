use thiserror::Error;

/// Every way an authorization check can fail. Variants are deliberately
/// specific — the server needs to distinguish "bad signature" from
/// "replayed" for logging and ban decisions, and the client needs to
/// distinguish "reject" from "transient" for grace-period handling.
#[derive(Debug, Error)]
pub enum KeystoneError {
    #[error("signature verification failed")]
    InvalidSignature,

    #[error("untrusted issuer key {key_id}")]
    UntrustedIssuer { key_id: u8 },

    #[error("response MAC does not match")]
    InvalidMac,

    #[error("challenge does not match the outstanding request")]
    ChallengeMismatch,

    #[error("response was already consumed")]
    AlreadyConsumed,

    #[error("authorization expired")]
    Expired,

    #[error("session is revoked")]
    Revoked,

    #[error("audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch { expected: String, actual: String },

    #[error("operation mismatch: expected {expected}, got {actual}")]
    OperationMismatch { expected: String, actual: String },

    #[error("session mismatch")]
    SessionMismatch,

    #[error("no entitlement for product {0}")]
    NoEntitlement(String),

    #[error("grace period exhausted")]
    GraceExhausted,

    #[error("malformed payload: {0}")]
    Malformed(String),

    #[error("clock skew beyond tolerance")]
    ClockSkew,
}

pub type Result<T, E = KeystoneError> = std::result::Result<T, E>;
