//! Sealed payload artifacts and session-bound key wraps.
//!
//! Artifacts in the payload dir are stored encrypted — XChaCha20-Poly1305
//! under a key derived from a server-held artifact secret. The on-disk
//! blob is `nonce || ciphertext`; the nonce doubles as the HKDF salt so
//! every sealed artifact gets its own key even under one secret.
//!
//! The artifact key never crosses the wire raw: POST /payload carries it
//! wrapped under a key derived from the session key + request nonce, so
//! only the live session that asked can unwrap it. A captured manifest,
//! a captured blob, and a captured wrap are each useless alone.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::crypto::{derive_payload_key, DOMAIN_KEY_WRAP};
use crate::error::{KeystoneError, Result};

/// Largest artifact the server will seal or serve and the client will
/// download — a bound on the decrypt allocation and the download buffer.
pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

/// Sealed blob prefix length — the XChaCha20 nonce. Anything shorter
/// than nonce + Poly1305 tag cannot be a sealed artifact.
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// The artifact key wrapped for one session+nonce — the only form in
/// which it may cross the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyWrap {
    /// Fresh XChaCha20 nonce for the wrap itself — distinct from both
    /// the request nonce and the artifact nonce.
    #[serde(with = "serde_big_array::BigArray")]
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// The per-artifact decryption key: HKDF(artifact_secret,
/// salt=artifact_nonce, info=DOMAIN_PAYLOAD_KEY + context). `context`
/// is `crypto::artifact_context(product, version)` — a key derived for
/// one artifact opens no other.
pub fn artifact_key(artifact_secret: &[u8; 32], artifact_nonce: &[u8; 24], context: &[u8]) -> [u8; 32] {
    derive_payload_key(artifact_secret, artifact_nonce, context)
}

/// Recover an artifact's key from a sealed blob: the nonce is read from
/// the blob prefix, so the secret alone recovers the key.
pub fn artifact_key_for(
    artifact_secret: &[u8; 32],
    context: &[u8],
    sealed: &[u8],
) -> Result<[u8; 32]> {
    let nonce: [u8; 24] = sealed
        .get(..NONCE_LEN)
        .ok_or_else(|| KeystoneError::Malformed("artifact too short".into()))?
        .try_into()
        .expect("slice length checked");
    Ok(artifact_key(artifact_secret, &nonce, context))
}

/// Seal plaintext into the on-disk artifact format.
pub fn seal_artifact(
    artifact_secret: &[u8; 32],
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
    let nonce_arr: [u8; 24] = nonce.into();
    let key = artifact_key(artifact_secret, &nonce_arr, context);
    let ciphertext = XChaCha20Poly1305::new((&key).into())
        .encrypt(&nonce, plaintext)
        .map_err(|_| KeystoneError::Malformed("artifact seal failed".into()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_arr);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a sealed artifact with its key. Wrong key or any tampered
/// byte fails the Poly1305 tag — `InvalidMac`, no partial plaintext.
pub fn decrypt_artifact(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(KeystoneError::Malformed("artifact too short".into()));
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| KeystoneError::InvalidMac)
}

/// The key that wraps artifact keys on the wire: HKDF(session_key,
/// salt=request_nonce, info=DOMAIN_KEY_WRAP). Bound to one session and
/// one request — a wrap captured from either is dead material anywhere
/// else.
pub fn payload_wrap_key(session_key: &[u8; 32], request_nonce: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(request_nonce), session_key);
    let mut key = [0u8; 32];
    hk.expand(DOMAIN_KEY_WRAP, &mut key)
        .expect("32 bytes is within HKDF-SHA256 output limit");
    key
}

/// Wrap an artifact key under a wrap key for transport.
pub fn wrap_artifact_key(wrap_key: &[u8; 32], artifact_key: &[u8; 32]) -> KeyWrap {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
    let ciphertext = XChaCha20Poly1305::new(wrap_key.into())
        .encrypt(&nonce, artifact_key.as_ref())
        .expect("encrypting 32 bytes cannot fail");
    KeyWrap {
        nonce: nonce.into(),
        ciphertext,
    }
}

/// Client side: derive the wrap key from session material and unwrap
/// the artifact key. A tampered or foreign wrap fails the tag.
pub fn unwrap_artifact_key(
    session_key: &[u8; 32],
    request_nonce: &[u8; 32],
    wrap: &KeyWrap,
) -> Result<[u8; 32]> {
    let wrap_key = payload_wrap_key(session_key, request_nonce);
    let plaintext = XChaCha20Poly1305::new((&wrap_key).into())
        .decrypt(XNonce::from_slice(&wrap.nonce), wrap.ciphertext.as_ref())
        .map_err(|_| KeystoneError::InvalidMac)?;
    plaintext
        .try_into()
        .map_err(|_| KeystoneError::Malformed("wrapped key wrong length".into()))
}
