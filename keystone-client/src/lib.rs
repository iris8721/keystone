//! keystone-client: the SDK loaders and payloads link against to consume a
//! keystone server.
//!
//! A loader exchanges credentials for a session, keeps it alive with
//! [`KeystoneClient::run_keepalive`], and launches its payload with a
//! single-use [`HandoffToken`]. The payload redeems the token for a session
//! of its own and checks [`SessionGate`] before protected operations. Every
//! signed value is verified against the [`TrustedIssuers`] baked into the
//! build.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod admin;
mod client;
mod error;
pub mod handoff;
mod session;
mod transport;

pub use admin::{AdminClient, AdminClientBuilder};
pub use client::{ClientBuilder, KeystoneClient, Payload};
pub use error::ClientError;
pub use session::{ClientSession, PendingSession, SessionGate};
pub use transport::ClientIdentity;

pub use keystone_core::wire::{DEFAULT_HANDOFF_TTL, ErrorCode, PublishBody, RevokeBody, Verdict};
pub use keystone_core::{
    BackendError, DeadReason, FeatureGrant, HandoffToken, KeystoneError, Manifest, SignedManifest,
    TrustedIssuers, VerifyingKey,
};
