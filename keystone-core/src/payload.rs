//! Sealed payload artifacts, their on-disk layout, and key wraps.
//!
//! A sealed artifact is `nonce || XChaCha20-Poly1305 ciphertext` under a
//! key derived from a server secret, the nonce, and the artifact context.
//! Keys cross the wire only as [`KeyWrap`]s under a wrap key that one
//! live session derives for one request.

use std::path::{Path, PathBuf};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{DOMAIN_PAYLOAD_WRAP, derive_payload_key, hkdf32};
use crate::error::{KeystoneError, Result};

/// Largest artifact the server seals or serves and the client downloads.
pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

/// Bytes at the start of a sealed artifact that, with the secret and the
/// context, determine its key: the XChaCha20 nonce.
pub const SEALED_PREFIX_LEN: usize = 24;

const TAG_LEN: usize = 16;

/// Whether `s` is safe as a single path segment on every OS: non-empty
/// ASCII alphanumerics plus `.`, `_`, `-`; not starting or ending with
/// `.`; no `..`; and not a Windows device name (`CON`, `PRN`, `AUX`,
/// `NUL`, `COM0`-`COM9`, `LPT0`-`LPT9`, any case, with or without an
/// extension).
pub fn valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
        && !is_windows_device_name(s)
}

/// Windows maps these stems to devices regardless of extension. Callers
/// pass ASCII only.
fn is_windows_device_name(s: &str) -> bool {
    let stem = s.split('.').next().unwrap_or(s);
    match stem.len() {
        3 => ["CON", "PRN", "AUX", "NUL"]
            .iter()
            .any(|name| stem.eq_ignore_ascii_case(name)),
        4 => {
            (stem[..3].eq_ignore_ascii_case("COM") || stem[..3].eq_ignore_ascii_case("LPT"))
                && stem.as_bytes()[3].is_ascii_digit()
        }
        _ => false,
    }
}

/// Where one release lives under a payload directory:
/// `{dir}/{product}/{version}.bin` plus `.sha256` (hex plaintext hash)
/// and `.build` (build id) sidecars.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPaths {
    /// The sealed artifact.
    pub sealed: PathBuf,
    /// Hex sha256 of the plaintext.
    pub sha256: PathBuf,
    /// The build id.
    pub build: PathBuf,
}

impl ArtifactPaths {
    /// Resolve the layout; `Malformed` unless product and version both
    /// pass [`valid_segment`].
    pub fn new(dir: impl AsRef<Path>, product: &str, version: &str) -> Result<Self> {
        if !valid_segment(product) || !valid_segment(version) {
            return Err(KeystoneError::Malformed(
                "invalid product or version".into(),
            ));
        }
        let base = dir.as_ref().join(product);
        Ok(Self {
            sealed: base.join(format!("{version}.bin")),
            sha256: base.join(format!("{version}.sha256")),
            build: base.join(format!("{version}.build")),
        })
    }
}

/// A 32-byte secret encrypted under a wrap key for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyWrap {
    /// Fresh XChaCha20 nonce for this wrap.
    pub nonce: [u8; 24],
    /// The wrapped secret plus its Poly1305 tag.
    pub ciphertext: Vec<u8>,
}

/// The per-artifact key from the first [`SEALED_PREFIX_LEN`] bytes of a
/// sealed artifact: HKDF(secret, salt = prefix, info = payload-key domain
/// || context). The server never reads more than the prefix to key it.
pub fn artifact_key_from_prefix(
    artifact_secret: &[u8; 32],
    context: &[u8],
    prefix: &[u8; SEALED_PREFIX_LEN],
) -> Zeroizing<[u8; 32]> {
    derive_payload_key(artifact_secret, prefix, context)
}

/// Seal plaintext into the on-disk artifact format.
pub fn seal_artifact(
    artifact_secret: &[u8; 32],
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
    let nonce_bytes: [u8; SEALED_PREFIX_LEN] = nonce.into();
    let key = artifact_key_from_prefix(artifact_secret, context, &nonce_bytes);
    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(&nonce, plaintext)
        .map_err(|_| KeystoneError::Malformed("artifact seal failed".into()))?;
    let mut out = Vec::with_capacity(SEALED_PREFIX_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a sealed artifact. Too short is `Malformed`; a wrong key or
/// any tampered byte is `InvalidMac`, with no partial plaintext.
pub fn decrypt_artifact(key: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < SEALED_PREFIX_LEN + TAG_LEN {
        return Err(KeystoneError::Malformed("artifact too short".into()));
    }
    let (nonce, ciphertext) = sealed.split_at(SEALED_PREFIX_LEN);
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| KeystoneError::InvalidMac)
}

/// The key that wraps an artifact key for one session and one request:
/// HKDF(session key, salt = request nonce, info = payload-wrap domain).
pub fn payload_wrap_key(session_key: &[u8; 32], request_nonce: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf32(session_key, Some(request_nonce), DOMAIN_PAYLOAD_WRAP)
}

/// Encrypt a 32-byte secret under `wrap_key` with a fresh nonce.
pub fn wrap_secret(wrap_key: &[u8; 32], secret: &[u8; 32]) -> KeyWrap {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
    let ciphertext = XChaCha20Poly1305::new(wrap_key.into())
        .encrypt(&nonce, secret.as_ref())
        .expect("encrypting 32 bytes cannot fail");
    KeyWrap {
        nonce: nonce.into(),
        ciphertext,
    }
}

/// Decrypt a [`KeyWrap`]. A wrong key or tampered wrap is `InvalidMac`;
/// a plaintext that is not 32 bytes is `Malformed`.
pub fn unwrap_secret(wrap_key: &[u8; 32], wrap: &KeyWrap) -> Result<Zeroizing<[u8; 32]>> {
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new(wrap_key.into())
            .decrypt(XNonce::from_slice(&wrap.nonce), wrap.ciphertext.as_ref())
            .map_err(|_| KeystoneError::InvalidMac)?,
    );
    if plaintext.len() != 32 {
        return Err(KeystoneError::Malformed("wrapped key wrong length".into()));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&plaintext);
    Ok(out)
}

/// Derive the payload wrap key and unwrap the artifact key it protects.
pub fn unwrap_artifact_key(
    session_key: &[u8; 32],
    request_nonce: &[u8; 32],
    wrap: &KeyWrap,
) -> Result<Zeroizing<[u8; 32]>> {
    unwrap_secret(&payload_wrap_key(session_key, request_nonce), wrap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_paths_use_product_dir_and_sidecars() {
        let paths = ArtifactPaths::new("payloads", "prod", "1.0").unwrap();
        let base = Path::new("payloads").join("prod");
        assert_eq!(paths.sealed, base.join("1.0.bin"));
        assert_eq!(paths.sha256, base.join("1.0.sha256"));
        assert_eq!(paths.build, base.join("1.0.build"));
    }

    #[test]
    fn artifact_paths_reject_escaping_segments() {
        for bad in [
            "", "..", "a..b", ".hidden", "a/b", "a\\b", "c:", "x y", "1.0.", "v ",
        ] {
            assert!(
                ArtifactPaths::new("payloads", bad, "1.0").is_err(),
                "product {bad:?} accepted"
            );
            assert!(
                ArtifactPaths::new("payloads", "prod", bad).is_err(),
                "version {bad:?} accepted"
            );
        }
    }

    #[test]
    fn windows_device_names_are_rejected_with_or_without_extension() {
        for bad in [
            "CON",
            "con",
            "Prn",
            "aux.bin",
            "NUL.tar.gz",
            "COM0",
            "com9.txt",
            "LPT1",
            "lpt5.x",
        ] {
            assert!(!valid_segment(bad), "{bad:?} accepted");
        }
        // Only the exact stems are devices.
        for good in [
            "CONSOLE", "nul1", "COM10", "LPT", "prod.con", "a-aux", "COMx",
        ] {
            assert!(valid_segment(good), "{good:?} rejected");
        }
    }

    #[test]
    fn prefix_alone_recovers_the_artifact_key() {
        let secret = [7u8; 32];
        let context = crate::crypto::artifact_context("prod", "1.0", 0);
        let sealed = seal_artifact(&secret, &context, b"bytes").unwrap();
        let prefix: &[u8; SEALED_PREFIX_LEN] = sealed[..SEALED_PREFIX_LEN].try_into().unwrap();
        let key = artifact_key_from_prefix(&secret, &context, prefix);
        assert_eq!(
            decrypt_artifact(&key, &sealed).unwrap().as_slice(),
            b"bytes"
        );
    }

    #[test]
    fn wrap_round_trips_only_under_its_key() {
        let wrap_key = payload_wrap_key(&[1u8; 32], &[2u8; 32]);
        let wrap = wrap_secret(&wrap_key, &[3u8; 32]);
        assert_eq!(*unwrap_secret(&wrap_key, &wrap).unwrap(), [3u8; 32]);
        let other = payload_wrap_key(&[1u8; 32], &[4u8; 32]);
        assert!(matches!(
            unwrap_secret(&other, &wrap),
            Err(KeystoneError::InvalidMac)
        ));
    }
}
