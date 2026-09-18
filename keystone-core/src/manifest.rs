//! Signed payload manifests — the artifact half of "download ≠ runtime".
//!
//! A manifest binds a product/version to the sha256 of the exact bytes
//! the server released, plus the per-feature grants the payload checks
//! at runtime. It is signed by the issuer and session-gated at fetch:
//! a captured manifest is worthless without a live session, because the
//! payload key it accompanies is derived from the session key.

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::{self, DOMAIN_MANIFEST};
use crate::error::{KeystoneError, Result};

/// What the server attests about one release artifact: which bytes are
/// the real payload and which features those bytes may enable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub product: String,
    pub version: String,
    /// Per-release identifier stamped at seal time (DESIGN.md:
    /// deterrence layer — a leaked build's manifest ties it to the
    /// release that produced it). Signed like every other field so
    /// attribution can't be rewritten. `default` keeps manifests
    /// issued before this field existed deserializable.
    #[serde(default)]
    pub build_id: String,
    /// Per-download identifier the server stamps on each manifest
    /// response — HMAC(watermark_secret, account‖session‖build_id‖
    /// issued_at). Core only carries and signs it; the server computes
    /// it so a captured manifest ties back to the exact download that
    /// produced it. `default` keeps manifests issued before this field
    /// existed deserializable.
    #[serde(default)]
    pub download_id: String,
    /// sha256 of the payload blob. Verified before the bytes are ever
    /// executed — a tampered download fails here, not at runtime.
    #[serde(with = "serde_big_array::BigArray")]
    pub sha256: [u8; 32],
    /// Server-issued per-feature grants (DESIGN.md: no local feature
    /// gating). The payload consults these at runtime; an expired grant
    /// means the feature is off even though the bytes are present.
    pub feature_grants: Vec<FeatureGrant>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A single feature grant inside a manifest. Expiry is per-grant so a
/// feature can lapse without reissuing the whole manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureGrant {
    pub feature: String,
    pub expires_at: DateTime<Utc>,
}

/// A manifest plus the issuer's signature over its canonical bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest: Manifest,
    /// Ed25519 signature over `manifest.canonical_bytes()`.
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 64],
}

impl Manifest {
    /// Canonical signed bytes — same construction as
    /// `Envelope::canonical_bytes`: domain separator, then explicit
    /// length-prefixed fields so the wire format and the signed format
    /// can never disagree.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(DOMAIN_MANIFEST);
        push_str(&mut buf, &self.product);
        push_str(&mut buf, &self.version);
        push_str(&mut buf, &self.build_id);
        push_str(&mut buf, &self.download_id);
        buf.extend_from_slice(&self.sha256);
        buf.extend_from_slice(&(self.feature_grants.len() as u32).to_be_bytes());
        for grant in &self.feature_grants {
            push_str(&mut buf, &grant.feature);
            buf.extend_from_slice(&grant.expires_at.timestamp_millis().to_be_bytes());
        }
        buf.extend_from_slice(&self.issued_at.timestamp_millis().to_be_bytes());
        buf.extend_from_slice(&self.expires_at.timestamp_millis().to_be_bytes());
        buf
    }

    /// Constant-time sha256 check of downloaded payload bytes against
    /// the hash the signature attests. Callers must refuse to run
    /// anything this rejects.
    pub fn verify_payload(&self, bytes: &[u8]) -> Result<()> {
        let actual: [u8; 32] = Sha256::digest(bytes).into();
        if actual.ct_eq(&self.sha256).into() {
            Ok(())
        } else {
            Err(KeystoneError::Malformed("payload sha256 mismatch".into()))
        }
    }

    /// Whether `name` is granted and unexpired at `now`. The manifest
    /// itself must still be live — an expired manifest grants nothing,
    /// and an expired grant is indistinguishable from an absent one.
    pub fn has_feature(&self, name: &str, now: DateTime<Utc>) -> bool {
        if now >= self.expires_at {
            return false;
        }
        self.feature_grants
            .iter()
            .any(|g| g.feature == name && g.is_active(now))
    }
}

impl FeatureGrant {
    /// A grant is active strictly before its expiry — at `expires_at`
    /// the feature is already off.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }
}

impl SignedManifest {
    /// Manifests issued further than this in the future are rejected —
    /// same rule as `Envelope`: a future-dated attestation is either a
    /// forged timestamp or a broken clock.
    const MAX_FUTURE_SKEW: chrono::Duration = chrono::Duration::seconds(30);

    /// Server-side: sign a manifest. The signature covers every field
    /// through `canonical_bytes`, so nothing attested can drift from
    /// what was signed.
    pub fn issue(issuer: &crypto::Issuer, manifest: Manifest) -> Self {
        let signature = issuer.sign(&manifest.canonical_bytes());
        Self {
            manifest,
            signature,
        }
    }

    /// Client-side: verify the signature, then freshness and expiry.
    /// Returns the attested manifest only when every check passes.
    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<&Manifest> {
        crypto::verify(key, &self.manifest.canonical_bytes(), &self.signature)?;
        if self.manifest.issued_at > now + Self::MAX_FUTURE_SKEW {
            return Err(KeystoneError::ClockSkew);
        }
        if now >= self.manifest.expires_at {
            return Err(KeystoneError::Expired);
        }
        Ok(&self.manifest)
    }
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}
