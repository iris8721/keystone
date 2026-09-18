//! Client-side error taxonomy.
//!
//! The distinctions mirror what the state machine needs: `ServerRejected`
//! carries the HTTP status so heartbeat can tell "denied, die now" (403/410)
//! from "unknown, burn grace" (404/409/5xx), and `GraceExhausted` is the
//! *client's own* decision — the server may be unreachable and never get a
//! vote.

use keystone_core::KeystoneError;

/// Every way a client operation can fail.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A core check failed — signature, MAC, challenge echo, expiry.
    /// These mean the *response* was untrustworthy, not that the
    /// session is dead.
    #[error(transparent)]
    Core(#[from] KeystoneError),

    /// Transport failure — DNS, connect, TLS, timeout. Always
    /// transient: the server never saw the request, so its view of the
    /// session is unchanged.
    #[error(transparent)]
    Transport(#[from] reqwest::Error),

    /// The server answered with a non-2xx status and an `{"error"}`
    /// body. The session's fate is decided by the optional `code`
    /// first — `bad_challenge`, `artifact_not_found`,
    /// `session_not_active`, `rate_limited` are transient — then by
    /// `status`: 403/410 without a transient code are explicit
    /// rejections, everything else is treated as transient.
    #[error("server rejected request: {status} {message}")]
    ServerRejected { status: u16, message: String },

    /// An operation that needs a live session was attempted on one
    /// that never authenticated or is already dead.
    #[error("session is not authenticated")]
    NotAuthenticated,

    /// The grace deadline passed while the server was unreachable.
    /// Distinct from `KeystoneError::GraceExhausted`: the server never
    /// ruled on this — the client decided locally, per the lease's
    /// fixed grace window.
    #[error("grace period exhausted")]
    GraceExhausted,

    /// Session key material is gone — the session was killed and its
    /// key dropped, so no further MACs can be produced.
    #[error("session key material unavailable")]
    MissingSessionKey,

    /// `new`/`new_unpinned_webpki` require an https base URL — plaintext
    /// transport would expose credentials and session material to
    /// anyone on the path. `KeystoneClient::new_insecure` exists for
    /// dev/test only.
    #[error("base_url must be https (KeystoneClient::new_insecure exists for dev/test): {0}")]
    InsecureBaseUrl(String),

    /// TLS configuration failed at construction — a malformed CA or
    /// client-certificate PEM, or a rustls build error. Surfaces
    /// before any request is attempted.
    #[error("TLS configuration failed: {0}")]
    Tls(String),
}
