//! Client-side error taxonomy.

use keystone_core::wire::{ErrorCode, Verdict};
use keystone_core::{BackendError, KeystoneError};

/// Every way a client operation can fail.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// A local check failed before or instead of a request: request
    /// validation, handoff token opening, a failed verification task.
    #[error(transparent)]
    Core(#[from] KeystoneError),

    /// The server answered 2xx but the response failed verification:
    /// signature, challenge, scope, freshness, body shape, or payload hash.
    /// Nothing it carried was accepted.
    #[error("invalid server response: {0}")]
    InvalidResponse(#[source] KeystoneError),

    /// The server answered non-2xx. `code` is `None` when the body was not
    /// a keystone `ErrorBody`, which is always treated as transient.
    #[error("server rejected request: {status} {message}")]
    ServerRejected {
        /// HTTP status.
        status: u16,
        /// Keystone error code, when the body carried one.
        code: Option<ErrorCode>,
        /// Human-readable reason.
        message: String,
    },

    /// Connect, TLS, timeout, or body transfer failure.
    #[error(transparent)]
    Transport(#[from] reqwest::Error),

    /// A response body delivered no bytes for `idle`. Transient, like a
    /// transport failure.
    #[error("response body stalled for {idle:?}")]
    Stalled {
        /// The idle window that elapsed.
        idle: std::time::Duration,
    },

    /// The session is dead or its lease no longer authorizes anything;
    /// the reason is available from `dead_reason()`.
    #[error("session is not authenticated")]
    NotAuthenticated,

    /// Builder input was rejected: URL, PEM material, TLS setup, or admin
    /// token. `source` carries the underlying parser or TLS error.
    #[error("invalid client configuration: {message}")]
    InvalidConfig {
        /// What was rejected.
        message: String,
        /// The error that caused the rejection, if any.
        #[source]
        source: Option<BackendError>,
    },
}

impl ClientError {
    /// Whether retrying the same operation later can succeed: transport
    /// failures, unverifiable responses, code-less rejections, and
    /// rejections whose code has a transient verdict.
    pub fn is_retryable(&self) -> bool {
        match self {
            ClientError::Transport(_)
            | ClientError::Stalled { .. }
            | ClientError::InvalidResponse(_) => true,
            ClientError::ServerRejected { code, .. } => {
                matches!(session_verdict(*code), Verdict::Transient)
            }
            ClientError::Core(_)
            | ClientError::NotAuthenticated
            | ClientError::InvalidConfig { .. } => false,
        }
    }

    pub(crate) fn config(message: impl Into<String>) -> Self {
        ClientError::InvalidConfig {
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn config_from(message: impl Into<String>, source: impl Into<BackendError>) -> Self {
        ClientError::InvalidConfig {
            message: message.into(),
            source: Some(source.into()),
        }
    }
}

/// The session verdict for a rejection; a response without a keystone
/// error code is transient.
pub(crate) fn session_verdict(code: Option<ErrorCode>) -> Verdict {
    code.map_or(Verdict::Transient, ErrorCode::verdict)
}
