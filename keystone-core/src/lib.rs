//! Server-authoritative licensing and session primitives shared by the
//! keystone server and client: signed challenge-bound envelopes, leases
//! with fixed grace deadlines, replay rejection, single-use handoffs,
//! session-bound payload keys, and the [`wire`] contract.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod accounts;
pub mod challenge;
pub mod crypto;
pub mod entitlement;
pub mod envelope;
pub mod error;
pub mod fs;
pub mod handoff;
pub mod issuers;
pub mod lease;
pub mod manifest;
pub mod payload;
pub mod replay;
pub mod revocations;
pub mod wire;

/// Ed25519 public key type used by [`TrustedIssuers`] and [`Issuer::verifying_key`].
pub use ed25519_dalek::VerifyingKey;

pub use accounts::{AccountFile, AccountGrant, AccountRecord};
pub use challenge::Challenge;
pub use crypto::{
    Issuer, KEYFILE_LEN, REQUEST_SKEW, RequestBinding, artifact_context, check_request_freshness,
    derive_watermark_secret, mac_request, request_nonce_expiry, verify_request_mac,
};
pub use entitlement::{AccountIdentity, Entitlement, EntitlementSource};
pub use envelope::{BootstrapExpectation, Envelope, Expectation, IssueSpec};
pub use error::{BackendError, KeystoneError, Result};
pub use handoff::{HandoffPayload, HandoffToken, handoff_wrap_key};
pub use issuers::TrustedIssuers;
pub use lease::{DeadReason, Lease, SessionState};
pub use manifest::{FeatureGrant, Manifest, SignedManifest};
pub use payload::{
    ArtifactPaths, KeyWrap, MAX_ARTIFACT_BYTES, SEALED_PREFIX_LEN, artifact_key_from_prefix,
    decrypt_artifact, payload_wrap_key, seal_artifact, unwrap_artifact_key, unwrap_secret,
    valid_segment, wrap_secret,
};
pub use replay::ConsumedSet;
