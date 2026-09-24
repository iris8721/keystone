//! Signing keys, request MACs, and HKDF derivations.

use std::fmt;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{KeystoneError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Domain separator for envelope signatures.
pub const DOMAIN_ENVELOPE: &[u8] = b"keystone.envelope.v2";
/// Domain separator for session-bound request MACs.
pub const DOMAIN_REQUEST_MAC: &[u8] = b"keystone.request-mac.v1";
/// HKDF domain for per-artifact payload keys.
pub const DOMAIN_PAYLOAD_KEY: &[u8] = b"keystone.payload-key.v2";
/// Domain separator for manifest signatures.
pub const DOMAIN_MANIFEST: &[u8] = b"keystone.manifest.v3";
/// HKDF domain for the key that wraps artifact keys to one session and request.
pub const DOMAIN_PAYLOAD_WRAP: &[u8] = b"keystone.payload-wrap.v1";
/// HKDF domain for the key that wraps a child session key to one handoff.
pub const DOMAIN_HANDOFF_WRAP: &[u8] = b"keystone.handoff-wrap.v1";
/// HKDF domain for the manifest watermark secret.
pub const DOMAIN_WATERMARK: &[u8] = b"keystone.watermark.v1";

/// Size of a key file: one key id byte followed by the 32-byte Ed25519 seed.
pub const KEYFILE_LEN: usize = 33;

/// Length-prefixed product/version/epoch binding for artifact keys.
/// Length prefixes keep ("a", "b:c") and ("a:b", "c") distinct; the
/// trailing epoch lets the server retire every key derived under an
/// earlier epoch without touching the secret.
pub fn artifact_context(product: &str, version: &str, epoch: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + product.len() + version.len());
    buf.extend_from_slice(&(product.len() as u32).to_be_bytes());
    buf.extend_from_slice(product.as_bytes());
    buf.extend_from_slice(&(version.len() as u32).to_be_bytes());
    buf.extend_from_slice(version.as_bytes());
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf
}

/// Server-side Ed25519 signing key and the id it signs under. The id
/// travels inside every signed value so verifiers can select, and
/// revoke, keys by id. The seed is wiped on drop.
pub struct Issuer {
    signing: SigningKey,
    key_id: u8,
}

impl Issuer {
    /// A fresh random key under `key_id`.
    pub fn generate(key_id: u8) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed[..]);
        Self {
            signing: SigningKey::from_bytes(&seed),
            key_id,
        }
    }

    /// Parse a key file (`key_id || seed`, exactly [`KEYFILE_LEN`] bytes).
    /// Any other length is `Malformed`.
    pub fn from_keyfile(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEYFILE_LEN {
            return Err(KeystoneError::Malformed(format!(
                "key file must be {KEYFILE_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes[1..]);
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
            key_id: bytes[0],
        })
    }

    /// The key file encoding accepted by [`Issuer::from_keyfile`].
    pub fn keyfile_bytes(&self) -> Zeroizing<[u8; KEYFILE_LEN]> {
        let mut out = Zeroizing::new([0u8; KEYFILE_LEN]);
        out[0] = self.key_id;
        out[1..].copy_from_slice(self.signing.as_bytes());
        out
    }

    /// The id this issuer signs under.
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    /// The public half, for a verifier's [`crate::TrustedIssuers`].
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Sign bytes the caller already canonicalized.
    pub fn sign(&self, canonical: &[u8]) -> [u8; 64] {
        self.signing.sign(canonical).to_bytes()
    }
}

impl fmt::Debug for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issuer")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Verify a signature over canonical bytes. Any failure is
/// `InvalidSignature`.
pub fn verify(key: &VerifyingKey, canonical: &[u8], signature: &[u8; 64]) -> Result<()> {
    let sig = Signature::from_bytes(signature);
    key.verify(canonical, &sig)
        .map_err(|_| KeystoneError::InvalidSignature)
}

/// How far a request's `issued_at` may sit from the server clock. It is
/// also the replay window: past `issued_at + REQUEST_SKEW` the timestamp
/// alone rejects a replay, so the nonce can be forgotten.
pub const REQUEST_SKEW: chrono::Duration = chrono::Duration::minutes(5);

/// Reject a request whose timestamp is outside `now ± REQUEST_SKEW`
/// (edges inclusive) with `ClockSkew`.
pub fn check_request_freshness(issued_at: DateTime<Utc>, now: DateTime<Utc>) -> Result<()> {
    if issued_at > now + REQUEST_SKEW || issued_at < now - REQUEST_SKEW {
        return Err(KeystoneError::ClockSkew);
    }
    Ok(())
}

/// When a consumed request nonce may be forgotten: the instant the
/// freshness check alone rejects a replay of it.
pub fn request_nonce_expiry(issued_at: DateTime<Utc>) -> DateTime<Utc> {
    issued_at + REQUEST_SKEW
}

/// Everything a session-bound request MAC covers. `context` comes from
/// [`crate::wire::mac_context`]; `issued_at` is bound at millisecond
/// precision, the precision it has on the wire.
#[derive(Debug, Clone, Copy)]
pub struct RequestBinding<'a> {
    /// Session the request acts on.
    pub session_id: &'a Uuid,
    /// Requester-minted nonce.
    pub nonce: &'a [u8; 32],
    /// Requester's clock when the request was minted.
    pub issued_at: DateTime<Utc>,
    /// Operation-specific canonical bytes.
    pub context: &'a [u8],
}

/// HMAC-SHA256 of a request binding under `key`. A tag cannot move to
/// another session, operation, nonce, or time.
pub fn mac_request(key: &[u8], binding: &RequestBinding<'_>) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(DOMAIN_REQUEST_MAC);
    mac.update(binding.session_id.as_bytes());
    mac.update(binding.nonce);
    mac.update(&binding.issued_at.timestamp_millis().to_be_bytes());
    mac.update(&(binding.context.len() as u32).to_be_bytes());
    mac.update(binding.context);
    mac.finalize().into_bytes().into()
}

/// Constant-time check of a request MAC; mismatch is `InvalidMac`.
pub fn verify_request_mac(
    key: &[u8],
    binding: &RequestBinding<'_>,
    expected: &[u8; 32],
) -> Result<()> {
    let actual = mac_request(key, binding);
    if subtle::ConstantTimeEq::ct_eq(&actual[..], &expected[..]).into() {
        Ok(())
    } else {
        Err(KeystoneError::InvalidMac)
    }
}

/// HKDF-SHA256 payload key: `ikm` is the server secret, `salt` the
/// per-artifact nonce, `context` from [`artifact_context`].
pub(crate) fn derive_payload_key(ikm: &[u8], salt: &[u8], context: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(DOMAIN_PAYLOAD_KEY.len() + context.len());
    info.extend_from_slice(DOMAIN_PAYLOAD_KEY);
    info.extend_from_slice(context);
    hkdf32(ikm, Some(salt), &info)
}

/// The manifest watermark secret derived from the payload secret, for
/// deployments that do not configure one explicitly.
pub fn derive_watermark_secret(payload_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf32(payload_secret, None, DOMAIN_WATERMARK)
}

/// 32 bytes of HKDF-SHA256 output.
pub(crate) fn hkdf32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(info, &mut out[..])
        .expect("32 bytes is within HKDF-SHA256 output limit");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_context_is_unambiguous() {
        assert_ne!(
            artifact_context("a", "b:c", 0),
            artifact_context("a:b", "c", 0)
        );
        assert_ne!(
            artifact_context("a:", "b", 0),
            artifact_context("a", ":b", 0)
        );
    }

    #[test]
    fn keyfile_round_trips_id_and_key() {
        let issuer = Issuer::generate(7);
        let bytes = issuer.keyfile_bytes();
        assert_eq!(bytes[0], 7);
        let back = Issuer::from_keyfile(&bytes[..]).unwrap();
        assert_eq!(back.key_id(), 7);
        assert_eq!(back.verifying_key(), issuer.verifying_key());
        let msg = b"canonical";
        verify(&issuer.verifying_key(), msg, &back.sign(msg)).expect("same key after reload");
    }

    #[test]
    fn keyfile_rejects_wrong_length() {
        let bytes = Issuer::generate(1).keyfile_bytes();
        // A bare 32-byte seed (the old format) and a padded file both fail.
        for len in [0, 32, 34] {
            let mut buf = bytes.to_vec();
            buf.resize(len, 0);
            assert!(matches!(
                Issuer::from_keyfile(&buf),
                Err(KeystoneError::Malformed(_))
            ));
        }
    }

    #[test]
    fn watermark_secret_is_domain_separated() {
        let secret = [9u8; 32];
        let watermark = derive_watermark_secret(&secret);
        assert_ne!(*watermark, secret);
        assert_ne!(*watermark, *derive_payload_key(&secret, &[], &[]));
    }
}
