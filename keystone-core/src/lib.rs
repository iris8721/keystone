//! keystone-core — server-authoritative auth primitives.
//!
//! Everything here implements the README contract: signed, fresh,
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
pub mod issuers;
pub mod lease;
pub mod manifest;
pub mod payload;
pub mod replay;
pub use accounts::{AccountFile, AccountGrant, AccountRecord};
pub use challenge::Challenge;
pub use crypto::{
    Issuer, REQUEST_SKEW, RequestBinding, artifact_context, check_request_freshness,
    derive_payload_key, mac_request, request_nonce_expiry, verify_request_mac,
};
pub use entitlement::{AccountIdentity, Entitlement, EntitlementSource};
pub use envelope::{Envelope, Expectation, IssueSpec};
pub use error::{KeystoneError, Result};
pub use handoff::{Handoff, HandoffPayload};
pub use issuers::TrustedIssuers;
pub use lease::{DeadReason, Lease, SessionState};
pub use manifest::{FeatureGrant, Manifest, SignedManifest};
pub use payload::{
    KeyWrap, MAX_ARTIFACT_BYTES, artifact_key, artifact_key_for, decrypt_artifact,
    payload_wrap_key, seal_artifact, unwrap_artifact_key, wrap_artifact_key,
};
pub use replay::ConsumedSet;
