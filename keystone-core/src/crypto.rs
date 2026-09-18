use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::error::{KeystoneError, Result};

type HmacSha256 = Hmac<Sha256>;

/// Domain separators — every signed/MAC'd/derived value is namespaced so
/// a signature for one purpose can never verify as another. A domain is
/// bumped whenever its canonical byte layout changes, so a value signed
/// under the old layout can never verify under the new one.
pub const DOMAIN_ENVELOPE: &[u8] = b"keystone.envelope.v2";
pub const DOMAIN_REQUEST_MAC: &[u8] = b"keystone.request-mac.v1";
pub const DOMAIN_PAYLOAD_KEY: &[u8] = b"keystone.payload-key.v2";
pub const DOMAIN_MANIFEST: &[u8] = b"keystone.manifest.v2";
pub const DOMAIN_KEY_WRAP: &[u8] = b"keystone.key-wrap.v1";

/// Length-prefixed product/version/epoch binding for artifact contexts.
/// `format!("{product}:{version}")` is ambiguous — ("a", "b:c") and
/// ("a:b", "c") produce the same string, so a key derived for one pair
/// could open an artifact sealed for another. Contexts are built here,
/// once, encoded the same way `canonical_bytes` encodes strings. The
/// trailing big-endian `epoch` (README: `HKDF(… || epoch)`) lets the
/// server rotate every payload key without touching the secret —
/// artifacts sealed under an earlier epoch stop opening.
pub fn artifact_context(product: &str, version: &str, epoch: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + product.len() + version.len());
    buf.extend_from_slice(&(product.len() as u32).to_be_bytes());
    buf.extend_from_slice(product.as_bytes());
    buf.extend_from_slice(&(version.len() as u32).to_be_bytes());
    buf.extend_from_slice(version.as_bytes());
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf
}

/// Server-side signing key. The private half NEVER ships — builds carry
/// only the verifying key. `key_id` names this key inside every value
/// it signs, so a verifier holding several trusted keys picks the right
/// one and a revoked key can be refused by id (README §Key rotation).
pub struct Issuer {
    signing: SigningKey,
    key_id: u8,
}

impl Issuer {
    /// Fresh random key under id 1 — the default for tests and for a
    /// server started without a configured key.
    pub fn generate() -> Self {
        Self::generate_with_id(1)
    }

    pub fn generate_with_id(key_id: u8) -> Self {
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
        Self::from_seed(&seed, key_id)
    }

    pub fn from_seed(seed: &[u8; 32], key_id: u8) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
            key_id,
        }
    }

    pub fn key_id(&self) -> u8 {
        self.key_id
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
pub fn verify(key: &VerifyingKey, canonical: &[u8], signature: &[u8; 64]) -> Result<()> {
    let sig = Signature::from_bytes(signature);
    key.verify(canonical, &sig)
        .map_err(|_| KeystoneError::InvalidSignature)
}

/// How far a session-bound request's `issued_at` may sit from the server's clock and still be
/// accepted; doubles as the replay window, since past `issued_at + REQUEST_SKEW` the timestamp alone
/// rejects a replay and the nonce can be forgotten.
pub const REQUEST_SKEW: chrono::Duration = chrono::Duration::minutes(5);

/// Reject a session-bound request whose timestamp is outside `now ± REQUEST_SKEW`.
pub fn check_request_freshness(
    issued_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    // Symmetric on purpose: a future-dated request is as suspicious as a
    // stale one, and the client stamps drift-adjusted time so an honest
    // skewed clock self-corrects after exchange.
    if issued_at > now + REQUEST_SKEW || issued_at < now - REQUEST_SKEW {
        return Err(KeystoneError::ClockSkew);
    }
    Ok(())
}

/// When a consumed request nonce may be forgotten: the moment the freshness check alone would
/// reject a replay of it.
pub fn request_nonce_expiry(
    issued_at: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    issued_at + REQUEST_SKEW
}

/// Everything a session-bound request MAC binds: the session, the client nonce, the client's
/// timestamp, and the operation context (`b"attest"`, `b"heartbeat"`, `b"payload.fetch:" ++
/// artifact_context`, ...).
pub struct RequestBinding<'a> {
    pub session_id: &'a Uuid,
    pub nonce: &'a [u8; 32],
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub context: &'a [u8],
}

/// MAC a session-bound request under the session key; a tag can't be moved to another session,
/// operation, artifact, or time because every binding is inside it.
pub fn mac_request(session_key: &[u8], binding: &RequestBinding<'_>) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(session_key).expect("HMAC accepts any key length");
    mac.update(DOMAIN_REQUEST_MAC);
    mac.update(binding.session_id.as_bytes());
    mac.update(binding.nonce);
    mac.update(&binding.issued_at.timestamp_millis().to_be_bytes());
    mac.update(&(binding.context.len() as u32).to_be_bytes());
    mac.update(binding.context);
    mac.finalize().into_bytes().into()
}

/// Constant-time request MAC check.
pub fn verify_request_mac(
    session_key: &[u8],
    binding: &RequestBinding<'_>,
    expected: &[u8; 32],
) -> Result<()> {
    let actual = mac_request(session_key, binding);
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
pub fn derive_payload_key(ikm: &[u8], salt: &[u8], context: &[u8]) -> [u8; 32] {
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
        assert_ne!(
            artifact_context("a", "b:c", 0),
            artifact_context("a:b", "c", 0)
        );
        assert_ne!(
            artifact_context("a:", "b", 0),
            artifact_context("a", ":b", 0)
        );
        assert_eq!(artifact_context("p", "v", 0), artifact_context("p", "v", 0));
    }

    #[test]
    fn artifact_context_encoding_is_length_prefixed() {
        let ctx = artifact_context("prod", "1.0", 0x0102_0304);
        let expected: &[u8] = b"\x00\x00\x00\x04prod\x00\x00\x00\x031.0\x01\x02\x03\x04";
        assert_eq!(ctx, expected);
    }

    #[test]
    fn issuer_carries_its_key_id() {
        assert_eq!(Issuer::generate().key_id(), 1);
        assert_eq!(Issuer::generate_with_id(7).key_id(), 7);
        assert_eq!(Issuer::from_seed(&[3u8; 32], 9).key_id(), 9);
    }
}
