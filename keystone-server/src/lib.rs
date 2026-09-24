//! keystone-server: the authority half of keystone. Every decision about
//! whether protected operations may run is made here; clients only hold
//! signed, expiring evidence of it.
//!
//! Embedders build an [`AppState`] and either call [`serve()`] or mount
//! [`public_router`] / [`admin_router`] themselves (see their docs for the
//! connection requirements, and call [`AppState::sweep`] on a timer).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod accounts;
pub mod audit;
pub mod config;
pub(crate) mod downloads;
pub mod entitlement;
pub mod error;
pub mod limiter;
pub mod revocations;
pub mod routes;
pub mod serve;
pub mod state;
pub mod store;
pub mod tls;

pub use audit::{AuditEvent, AuditSink, TracingAudit};
pub use config::{AdminToken, AdminTokenError, PayloadConfig, RateLimits, ServerConfig};
pub use error::ServerError;
pub use keystone_core::BackendError;
pub use limiter::{MemoryLimiter, RateLimiter};
pub use revocations::{FileRevocationStore, MemoryRevocations, RevocationStore};
pub use routes::{admin_router, public_router};
pub use serve::{Listeners, serve};
pub use state::{AppState, AppStateBuilder};
pub use store::{HandoffRecord, MemoryStore, SessionRecord, SessionStore};
pub use tls::TransportMode;
