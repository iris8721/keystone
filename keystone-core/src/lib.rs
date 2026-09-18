//! keystone-core — server-authoritative auth primitives.
//!
//! Everything here implements the DESIGN.md contract: signed, fresh,
//! scoped, single-use responses; bounded leases with fixed grace
//! deadlines; replay rejection; payload keys that only exist after a
//! live exchange.

pub mod accounts;
pub mod challenge;
pub mod crypto;
pub mod entitlement;
pub mod envelope;
pub mod error;
pub mod handoff;
pub mod lease;
pub mod manifest;
pub mod payload;
pub mod replay;
pub use accounts::{AccountFile, AccountGrant, AccountRecord};
pub use challenge::Challenge;
pub use crypto::{
    artifact_context, derive_payload_key, mac_heartbeat, mac_response, verify_heartbeat_mac,
    verify_response_mac, Issuer,
};
pub use entitlement::{AccountIdentity, Entitlement, EntitlementSource};
pub use envelope::{Envelope, Expectation, IssueSpec};
pub use error::{KeystoneError, Result};
pub use handoff::{Handoff, HandoffPayload};
pub use lease::{DeadReason, Lease, SessionState};
pub use manifest::{FeatureGrant, Manifest, SignedManifest};
pub use payload::{
    artifact_key, artifact_key_for, decrypt_artifact, payload_wrap_key, seal_artifact,
    unwrap_artifact_key, wrap_artifact_key, KeyWrap, MAX_ARTIFACT_BYTES,
};
pub use replay::ConsumedSet;
