//! Signed payload manifests and feature grants.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::crypto::{self, DOMAIN_MANIFEST};
use crate::error::{KeystoneError, Result};
use crate::issuers::TrustedIssuers;

/// What the server attests about one release artifact: which plaintext
/// bytes are the real payload, and which release and download produced
/// this copy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Product name.
    pub product: String,
    /// Release version.
    pub version: String,
    /// Per-release identifier stamped at seal time.
    pub build_id: String,
    /// Per-download watermark the server computes for each manifest.
    pub download_id: String,
    /// sha256 of the plaintext payload.
    pub sha256: [u8; 32],
    /// Server clock at issue.
    #[serde(with = "crate::wire::millis")]
    pub issued_at: DateTime<Utc>,
    /// First instant at which the manifest is dead.
    #[serde(with = "crate::wire::millis")]
    pub expires_at: DateTime<Utc>,
}

/// A named feature granted until `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureGrant {
    /// Feature name.
    pub feature: String,
    /// First instant at which the feature is off.
    #[serde(with = "crate::wire::millis")]
    pub expires_at: DateTime<Utc>,
}

/// A manifest plus the issuer's signature over it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    /// Issuer key that signed the manifest; covered by the signature.
    pub key_id: u8,
    /// The attested manifest.
    pub manifest: Manifest,
    /// Ed25519 signature over [`SignedManifest::canonical_bytes`].
    #[serde(with = "serde_big_array::BigArray")]
    pub signature: [u8; 64],
}

impl Manifest {
    /// The attested fields, length-prefixed; timestamps at millisecond
    /// precision.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            16 + self.product.len()
                + self.version.len()
                + self.build_id.len()
                + self.download_id.len()
                + 32
                + 16,
        );
        push_str(&mut buf, &self.product);
        push_str(&mut buf, &self.version);
        push_str(&mut buf, &self.build_id);
        push_str(&mut buf, &self.download_id);
        buf.extend_from_slice(&self.sha256);
        buf.extend_from_slice(&self.issued_at.timestamp_millis().to_be_bytes());
        buf.extend_from_slice(&self.expires_at.timestamp_millis().to_be_bytes());
        buf
    }

    /// Constant-time check of payload bytes against the attested hash;
    /// mismatch is `Malformed`. Callers must not run rejected bytes.
    pub fn verify_payload(&self, bytes: &[u8]) -> Result<()> {
        let actual: [u8; 32] = Sha256::digest(bytes).into();
        if actual.ct_eq(&self.sha256).into() {
            Ok(())
        } else {
            Err(KeystoneError::Malformed("payload sha256 mismatch".into()))
        }
    }
}

impl FeatureGrant {
    /// True strictly before `expires_at`.
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }
}

impl SignedManifest {
    /// How far in the future `issued_at` may sit relative to the
    /// verifier's clock.
    const MAX_FUTURE_SKEW: chrono::Duration = chrono::Duration::seconds(30);

    /// The signed bytes: domain, key id, then the manifest fields.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let fields = self.manifest.canonical_bytes();
        let mut buf = Vec::with_capacity(DOMAIN_MANIFEST.len() + 1 + fields.len());
        buf.extend_from_slice(DOMAIN_MANIFEST);
        buf.push(self.key_id);
        buf.extend_from_slice(&fields);
        buf
    }

    /// Sign a manifest under the issuer's key id.
    pub fn issue(issuer: &crypto::Issuer, manifest: Manifest) -> Self {
        let mut signed = Self {
            key_id: issuer.key_id(),
            manifest,
            signature: [0u8; 64],
        };
        signed.signature = issuer.sign(&signed.canonical_bytes());
        signed
    }

    /// Verify key trust and signature, then `ClockSkew` for a future
    /// `issued_at` and `Expired` at or past `expires_at`. Returns the
    /// manifest only when every check passes.
    pub fn verify(&self, issuers: &TrustedIssuers, now: DateTime<Utc>) -> Result<&Manifest> {
        let key = issuers.key_for(self.key_id)?;
        crypto::verify(key, &self.canonical_bytes(), &self.signature)?;
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
