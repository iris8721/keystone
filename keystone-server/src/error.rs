//! Startup, configuration, and storage failures.

use std::io;
use std::net::SocketAddr;

use keystone_core::BackendError;

/// Everything that can stop the server from starting, serving, or applying
/// an operator action. Request-level denials never surface here; they are
/// `wire::ErrorBody` responses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerError {
    /// A configuration value is missing or unusable. `var` names the
    /// environment variable for `ServerConfig::from_env`, and the builder
    /// method for `AppStateBuilder`.
    #[error("{var}: {message}")]
    Config {
        /// The environment variable or builder setting at fault.
        var: &'static str,
        /// What is wrong with it.
        message: String,
    },
    /// TLS material could not be loaded.
    #[error("tls: {0}")]
    Tls(#[source] io::Error),
    /// A listener could not be bound.
    #[error("bind {addr}: {source}")]
    Bind {
        /// The address that failed.
        addr: SocketAddr,
        /// The OS error.
        #[source]
        source: io::Error,
    },
    /// The session store failed.
    #[error("session store: {0}")]
    Store(#[source] BackendError),
    /// The revocation store failed.
    #[error("revocation store: {0}")]
    Revocations(#[source] BackendError),
    /// The active signing key id is revoked, or a caller tried to revoke it.
    #[error("issuer key {0} is the active signing key")]
    ActiveKeyRevoked(u8),
    /// A listener failed while serving.
    #[error("serve: {0}")]
    Serve(#[source] io::Error),
}

impl ServerError {
    pub(crate) fn config(var: &'static str, message: impl Into<String>) -> Self {
        ServerError::Config {
            var,
            message: message.into(),
        }
    }
}
