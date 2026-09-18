use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::{KeystoneError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Domain separators — every signed/MAC'd/derived value is namespaced so
/// a signature for one purpose can never verify as another.
pub const DOMAIN_ENVELOPE: &[u8] = b"keystone.envelope.v1";
pub const DOMAIN_RESPONSE_MAC: &[u8] = b"keystone.response-mac.v1";
pub const DOMAIN_PAYLOAD_KEY: &[u8] = b"keystone.payload-key.v1";
pub const DOMAIN_HEARTBEAT: &[u8] = b"keystone.heartbeat.v1";
pub const DOMAIN_MANIFEST: &[u8] = b"keystone.manifest.v1";
pub const DOMAIN_KEY_WRAP: &[u8] = b"keystone.key-wrap.v1";

/// Length-prefixed product/version binding for artifact contexts.
/// `format!("{product}:{version}")` is ambiguous — ("a", "b:c") and
/// ("a:b", "c") produce the same string, so a key derived for one pair
/// could open an artifact sealed for another. Contexts are built here,
/// once, encoded the same way `canonical_bytes` encodes strings.
pub fn artifact_context(product: &str, version: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + product.len() + version.len());
    buf.extend_from_slice(&(product.len() as u32).to_be_bytes());
    buf.extend_from_slice(product.as_bytes());
    buf.extend_from_slice(&(version.len() as u32).to_be_bytes());
    buf.extend_from_slice(version.as_bytes());
    buf
}

/// Server-side signing key. The private half NEVER ships — builds carry
/// only the verifying key.
pub struct Issuer {
    signing: SigningKey,
}

impl Issuer {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Sign already-canonicalized bytes. Callers build the byte string;
    /// this never sees raw structs, so the wire format and the signed
    /// format can never drift apart.
    pub fn sign(&self, canonical: &[u8]) -> [u8; 64] {
        self.signing.sign(canonical).to_bytes()
    }
}

/// Verify a signature over canonical bytes against a pinned verifying
/// key. Fails closed: any error is InvalidSignature, no partial credit.
pub fn verify(
    key: &VerifyingKey,
    canonical: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    let sig = Signature::from_bytes(signature);
    key.verify(canonical, &sig)
        .map_err(|_| KeystoneError::InvalidSignature)
}

/// MAC a response body so a captured response can't be replayed into a
/// different session or request. The MAC covers the session key, the
/// request nonce, and the body — all three must match.
pub fn mac_response(
    session_key: &[u8],
    request_nonce: &[u8],
    body: &[u8],
) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(session_key)
        .expect("HMAC accepts any key length");
    mac.update(DOMAIN_RESPONSE_MAC);
    mac.update(&(request_nonce.len() as u32).to_be_bytes());
    mac.update(request_nonce);
    mac.update(&(body.len() as u32).to_be_bytes());
    mac.update(body);
    mac.finalize().into_bytes().into()
}

/// Constant-time MAC check.
pub fn verify_response_mac(
    session_key: &[u8],
    request_nonce: &[u8],
    body: &[u8],
    expected: &[u8; 32],
) -> Result<()> {
    let actual = mac_response(session_key, request_nonce, body);
    if subtle::ConstantTimeEq::ct_eq(&actual[..], &expected[..]).into() {
        Ok(())
    } else {
        Err(KeystoneError::InvalidMac)
    }
}

/// MAC a heartbeat: DOMAIN_HEARTBEAT + session_id + nonce, keyed by the
/// session key. A heartbeat MAC can never verify as a response MAC and
/// can never be transplanted into another session — all three bindings
/// are inside the tag.
pub fn mac_heartbeat(session_key: &[u8], session_id: &Uuid, nonce: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(session_key)
        .expect("HMAC accepts any key length");
    mac.update(DOMAIN_HEARTBEAT);
    mac.update(session_id.as_bytes());
    mac.update(nonce);
    mac.finalize().into_bytes().into()
}

/// Constant-time heartbeat MAC check.
pub fn verify_heartbeat_mac(
    session_key: &[u8],
    session_id: &Uuid,
    nonce: &[u8; 32],
    expected: &[u8; 32],
) -> Result<()> {
    let actual = mac_heartbeat(session_key, session_id, nonce);
    if subtle::ConstantTimeEq::ct_eq(&actual[..], &expected[..]).into() {
        Ok(())
    } else {
        Err(KeystoneError::InvalidMac)
    }
}

/// Derive a payload decryption key from server-held secret material.
/// Static extraction of the client yields nothing — the key only exists
/// after a live exchange.
///
/// `ikm`     — license/session secret issued by the server
/// `salt`    — session public key or per-session random salt
/// `context` — product/version binding, built by `artifact_context`
pub fn derive_payload_key(
    ikm: &[u8],
    salt: &[u8],
    context: &[u8],
) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    let mut info = Vec::with_capacity(DOMAIN_PAYLOAD_KEY.len() + context.len());
    info.extend_from_slice(DOMAIN_PAYLOAD_KEY);
    info.extend_from_slice(context);
    hk.expand(&info, &mut out)
        .expect("32 bytes is within HKDF-SHA256 output limit");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_context_is_unambiguous() {
        // The whole point of the encoding: pairs whose naive
        // "{product}:{version}" strings collide must not collide here.
        assert_ne!(artifact_context("a", "b:c"), artifact_context("a:b", "c"));
        assert_ne!(artifact_context("a:", "b"), artifact_context("a", ":b"));
        assert_eq!(artifact_context("p", "v"), artifact_context("p", "v"));
    }

    #[test]
    fn artifact_context_encoding_is_length_prefixed() {
        let ctx = artifact_context("prod", "1.0");
        let expected: &[u8] = b"\x00\x00\x00\x04prod\x00\x00\x00\x031.0";
        assert_eq!(ctx, expected);
    }
}
