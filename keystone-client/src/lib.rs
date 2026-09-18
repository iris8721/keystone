//! keystone-client — the SDK loaders and payloads link against to
//! consume keystone-server.
//!
//! Implements the client half of the README contract: exchange
//! credentials for a signed, bounded session; attest independently from
//! the application side; renew the lease with MAC'd heartbeats; and
//! degrade into a fixed grace window — never silent trust — when the
//! server can't be reached.
//!
//! The client trusts exactly the issuer set baked into the build: a
//! `TrustedIssuers` map of key id to ed25519 verifying key. Every
//! envelope and manifest is verified against it before anything it
//! carries is believed. The set is never learned from a handoff or
//! the network — it only shrinks, when a key is revoked.

pub mod client;
pub mod error;
pub mod session;

pub use client::{ClientIdentity, KeystoneClient};
pub use error::ClientError;
pub use session::ClientSession;

// The app side of a handoff opens a `Handoff` — re-exported so a
// payload depending only on keystone-client can still name the type.
pub use keystone_core::{Handoff, HandoffPayload};
// Payload fetches return a `SignedManifest` — re-exported alongside so
// a payload crate needs only keystone-client on its dependency list.
pub use keystone_core::{FeatureGrant, Manifest, SignedManifest};
// Every constructor takes the trusted issuer set — re-exported so a
// consumer can build one without naming keystone-core.
pub use keystone_core::TrustedIssuers;
