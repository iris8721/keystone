//! Security-relevant events and where they go.

use keystone_core::wire::ErrorCode;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// One security-relevant event. Carries no secrets; session ids are raw so
/// a sink can correlate, and [`TracingAudit`] hashes them before logging.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEvent {
    /// A session was created by `/exchange`.
    ExchangeSucceeded {
        /// Account that logged in.
        account: String,
        /// Product of the session.
        product: String,
        /// The new session.
        session_id: Uuid,
    },
    /// `/exchange` refused an authenticated or unauthenticated request.
    ExchangeDenied {
        /// Account the request named.
        account: String,
        /// The code the caller received.
        reason: ErrorCode,
    },
    /// An account presented a different HWID fingerprint within the window.
    HwidAnomaly {
        /// The account.
        account: String,
    },
    /// A session minted a handoff.
    HandoffCreated {
        /// The minting session.
        parent: Uuid,
    },
    /// A handoff was redeemed for a child session.
    AttestSucceeded {
        /// The new child session.
        session_id: Uuid,
        /// The session that minted the handoff.
        parent: Uuid,
    },
    /// A session and its descendants were revoked.
    SessionRevoked {
        /// The revoked session.
        session_id: Uuid,
    },
    /// Every session of an account was revoked.
    AccountRevoked {
        /// The account.
        account: String,
        /// Sessions killed.
        sessions: u64,
    },
    /// An issuer key id was revoked and every session killed.
    KeyRevoked {
        /// The revoked key id.
        key_id: u8,
        /// Sessions killed.
        sessions: u64,
    },
    /// A payload manifest and wrapped key were issued.
    DownloadIssued {
        /// The session.
        session_id: Uuid,
        /// Product.
        product: String,
        /// Release version.
        version: String,
    },
    /// An operator published a release through the admin router.
    ArtifactPublished {
        /// Product.
        product: String,
        /// Release version.
        version: String,
        /// Build id stamped into its manifests.
        build_id: String,
    },
}

/// Receives every [`AuditEvent`]. Called inline on the request path, so
/// implementations must not block.
pub trait AuditSink: Send + Sync {
    /// Record one event.
    fn record(&self, event: AuditEvent);
}

/// Default sink: structured `tracing` events under target `keystone::audit`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingAudit;

impl AuditSink for TracingAudit {
    fn record(&self, event: AuditEvent) {
        match event {
            AuditEvent::ExchangeSucceeded {
                account,
                product,
                session_id,
            } => tracing::info!(
                target: "keystone::audit",
                account = %sanitize(&account),
                product = %sanitize(&product),
                session = %session_tag(&session_id),
                "exchange succeeded"
            ),
            AuditEvent::ExchangeDenied { account, reason } => tracing::warn!(
                target: "keystone::audit",
                account = %sanitize(&account),
                %reason,
                "exchange denied"
            ),
            AuditEvent::HwidAnomaly { account } => tracing::warn!(
                target: "keystone::audit",
                account = %sanitize(&account),
                "hwid anomaly: new fingerprint within window"
            ),
            AuditEvent::HandoffCreated { parent } => tracing::info!(
                target: "keystone::audit",
                parent = %session_tag(&parent),
                "handoff created"
            ),
            AuditEvent::AttestSucceeded { session_id, parent } => tracing::info!(
                target: "keystone::audit",
                session = %session_tag(&session_id),
                parent = %session_tag(&parent),
                "attest succeeded"
            ),
            AuditEvent::SessionRevoked { session_id } => tracing::info!(
                target: "keystone::audit",
                session = %session_tag(&session_id),
                "session revoked"
            ),
            AuditEvent::AccountRevoked { account, sessions } => tracing::info!(
                target: "keystone::audit",
                account = %sanitize(&account),
                sessions,
                "account revoked"
            ),
            AuditEvent::KeyRevoked { key_id, sessions } => tracing::warn!(
                target: "keystone::audit",
                key_id,
                sessions,
                "issuer key revoked"
            ),
            AuditEvent::DownloadIssued {
                session_id,
                product,
                version,
            } => tracing::info!(
                target: "keystone::audit",
                session = %session_tag(&session_id),
                product = %sanitize(&product),
                version = %sanitize(&version),
                "download issued"
            ),
            AuditEvent::ArtifactPublished {
                product,
                version,
                build_id,
            } => tracing::info!(
                target: "keystone::audit",
                product = %sanitize(&product),
                version = %sanitize(&version),
                build_id = %sanitize(&build_id),
                "artifact published"
            ),
        }
    }
}

/// Truncated sha256 of a session id: correlates log lines without
/// exposing the id itself.
pub(crate) fn session_tag(session_id: &Uuid) -> String {
    hex::encode(&Sha256::digest(session_id.as_bytes())[..8])
}

/// Client-supplied text reduced to `[A-Za-z0-9._-]`, at most 64 chars, so a
/// hostile value cannot forge log lines.
fn sanitize(s: &str) -> String {
    s.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '?'
            }
        })
        .collect()
}
