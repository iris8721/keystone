//! keystone-server — the authority half of the Keystone system.
//!
//! Hosts the exchange/attest/heartbeat/revoke endpoints from README.
//! Every check that decides whether protected operations may run lives
//! here; clients and applications only ever hold signed, expiring
//! evidence of a decision this server made.

pub mod accounts;
pub mod downloads;
pub mod entitlement;
pub mod routes;
pub mod state;
pub mod store;
pub mod tls;

pub use routes::build_router;
pub use state::AppState;
pub use store::SessionStore;
