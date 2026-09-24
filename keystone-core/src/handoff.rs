//! Encrypted loader-to-application handoff.
//!
//! The loader asks the server for a single-use handoff, seals the
//! handoff id and secret for the child's claimed `process_id`, and passes
//! the resulting [`HandoffToken`] through the launch channel. The loader
//! session key never enters the blob; the child redeems the handoff at
//! the server for a session of its own.
//!
//! The blob is XChaCha20-Poly1305 under an HKDF key whose info carries
//! `process_id`, so it opens only under the identity it was sealed for,
//! and its freshness window is authenticated as associated data. The
//! identity is a claimed name, not something the OS vouches for.

use std::fmt;
use std::io::{self, Read, Write};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadCore, AeadInPlace, KeyInit},
};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{DOMAIN_HANDOFF_WRAP, hkdf32};
use crate::error::{KeystoneError, Result};
use crate::wire::{MAX_HANDOFF_TTL, MAX_PRODUCT_LEN};

const DOMAIN_HANDOFF: &[u8] = b"keystone.handoff.v2";
const TOKEN_PREFIX: &str = "ksh2.";
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// Fixed-width part of the plaintext: parent id, handoff id, handoff
/// secret, expiry, server offset, product length.
const PAYLOAD_FIXED_LEN: usize = 16 + 32 + 32 + 8 + 8 + 4;
/// Fixed-width part of a decoded token: launch key, nonce, issued_at, ttl.
const TOKEN_FIXED_LEN: usize = 32 + NONCE_LEN + 8 + 8;
/// Longest token text accepted by `decode` and `read_from`.
const MAX_TOKEN_LEN: usize = 4096;

/// A sealed handoff blob. Only the nonce and freshness window are in the
/// clear, and both are authenticated.
#[derive(Clone)]
pub(crate) struct Handoff {
    /// XChaCha20 nonce; also the HKDF salt, so every blob has its own key.
    pub(crate) nonce: [u8; NONCE_LEN],
    /// Sealer's clock at seal time.
    pub(crate) issued_at: DateTime<Utc>,
    /// How long after `issued_at` the blob may be opened.
    pub(crate) ttl: Duration,
    /// Encrypted [`HandoffPayload`] plus tag.
    pub(crate) ciphertext: Vec<u8>,
}

/// What the child needs to redeem the handoff at `POST /attest`, and
/// nothing else. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HandoffPayload {
    /// The loader session that minted the handoff.
    #[zeroize(skip)]
    pub parent_session_id: Uuid,
    /// Identifies the handoff at the server.
    pub handoff_id: [u8; 32],
    /// Keys the attest MAC and the child session key wrap.
    pub handoff_secret: [u8; 32],
    /// Product the child session will be for.
    pub product: String,
    /// Server deadline for redeeming the handoff.
    #[zeroize(skip)]
    pub expires_at: DateTime<Utc>,
    /// Server clock minus the loader's clock, in milliseconds, so the
    /// child's first timestamp lands inside the server's window.
    pub server_offset_millis: i64,
}

/// A launch key plus the blob it opens: everything the child receives.
/// Text form is `ksh2.` followed by unpadded base64url.
pub struct HandoffToken {
    key: Zeroizing<[u8; 32]>,
    blob: Handoff,
}

/// The key that wraps the child session key in an attest body:
/// HKDF(handoff secret, salt = attest challenge, info = handoff-wrap domain).
pub fn handoff_wrap_key(handoff_secret: &[u8; 32], challenge: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf32(handoff_secret, Some(challenge), DOMAIN_HANDOFF_WRAP)
}

/// The AEAD for one blob; opening under another `process_id` derives a
/// different key and fails the tag.
fn cipher(handoff_key: &[u8; 32], nonce: &[u8; NONCE_LEN], process_id: &str) -> XChaCha20Poly1305 {
    let mut info = Vec::with_capacity(DOMAIN_HANDOFF.len() + process_id.len());
    info.extend_from_slice(DOMAIN_HANDOFF);
    info.extend_from_slice(process_id.as_bytes());
    let key = hkdf32(handoff_key, Some(nonce), &info);
    XChaCha20Poly1305::new((&*key).into())
}

fn aad(issued_at: DateTime<Utc>, ttl: Duration) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[..8].copy_from_slice(&issued_at.timestamp_millis().to_be_bytes());
    aad[8..].copy_from_slice(&ttl.num_milliseconds().to_be_bytes());
    aad
}

impl HandoffPayload {
    /// Binary plaintext with room for the tag, so sealing in place never
    /// reallocates and leaves no unwiped copy behind.
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let len = PAYLOAD_FIXED_LEN + self.product.len();
        let mut buf = Zeroizing::new(Vec::with_capacity(len + TAG_LEN));
        buf.extend_from_slice(self.parent_session_id.as_bytes());
        buf.extend_from_slice(&self.handoff_id);
        buf.extend_from_slice(&self.handoff_secret);
        buf.extend_from_slice(&self.expires_at.timestamp_millis().to_be_bytes());
        buf.extend_from_slice(&self.server_offset_millis.to_be_bytes());
        buf.extend_from_slice(&(self.product.len() as u32).to_be_bytes());
        buf.extend_from_slice(self.product.as_bytes());
        buf
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let malformed = || KeystoneError::Malformed("handoff payload".into());
        if bytes.len() < PAYLOAD_FIXED_LEN {
            return Err(malformed());
        }
        let (fixed, product) = bytes.split_at(PAYLOAD_FIXED_LEN);
        let product_len = u32::from_be_bytes(fixed[96..100].try_into().expect("4 bytes"));
        if product.len() != product_len as usize {
            return Err(malformed());
        }
        let expires_at = DateTime::from_timestamp_millis(i64::from_be_bytes(
            fixed[80..88].try_into().expect("8 bytes"),
        ))
        .ok_or_else(malformed)?;
        Ok(Self {
            parent_session_id: Uuid::from_bytes(fixed[..16].try_into().expect("16 bytes")),
            handoff_id: fixed[16..48].try_into().expect("32 bytes"),
            handoff_secret: fixed[48..80].try_into().expect("32 bytes"),
            product: String::from_utf8(product.to_vec()).map_err(|_| malformed())?,
            expires_at,
            server_offset_millis: i64::from_be_bytes(fixed[88..96].try_into().expect("8 bytes")),
        })
    }
}

impl Handoff {
    /// How far in the future `issued_at` may sit relative to the opener.
    const MAX_FUTURE_SKEW: Duration = Duration::seconds(30);

    /// Seal `payload` for `process_id` under `handoff_key`, openable for
    /// `ttl`. A ttl outside `(0, MAX_HANDOFF_TTL]` is `Malformed`; a
    /// product longer than `MAX_PRODUCT_LEN` is `FieldTooLong`.
    pub(crate) fn seal(
        handoff_key: &[u8; 32],
        payload: &HandoffPayload,
        process_id: &str,
        ttl: Duration,
    ) -> Result<Self> {
        if ttl <= Duration::zero() || ttl > MAX_HANDOFF_TTL {
            return Err(KeystoneError::Malformed(format!(
                "handoff ttl {ttl} outside (0, {MAX_HANDOFF_TTL}]"
            )));
        }
        if payload.product.len() > MAX_PRODUCT_LEN {
            return Err(KeystoneError::FieldTooLong("product"));
        }
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
        let nonce_bytes: [u8; NONCE_LEN] = nonce.into();
        let issued_at = Utc::now();
        let mut buf = payload.encode();
        cipher(handoff_key, &nonce_bytes, process_id)
            .encrypt_in_place(&nonce, &aad(issued_at, ttl), &mut *buf)
            .map_err(|_| KeystoneError::Malformed("handoff seal failed".into()))?;
        Ok(Self {
            nonce: nonce_bytes,
            issued_at,
            ttl,
            ciphertext: std::mem::take(&mut *buf),
        })
    }

    /// Open as `process_id` at `now`. The tag is checked before any
    /// timestamp: a wrong key, wrong recipient, or tampered byte is
    /// `InvalidMac`; only an authentic blob can be `ClockSkew` or `Expired`.
    pub(crate) fn open(
        &self,
        handoff_key: &[u8; 32],
        process_id: &str,
        now: DateTime<Utc>,
    ) -> Result<HandoffPayload> {
        let mut buf = Zeroizing::new(self.ciphertext.clone());
        cipher(handoff_key, &self.nonce, process_id)
            .decrypt_in_place(
                XNonce::from_slice(&self.nonce),
                &aad(self.issued_at, self.ttl),
                &mut *buf,
            )
            .map_err(|_| KeystoneError::InvalidMac)?;
        if self.issued_at > now + Self::MAX_FUTURE_SKEW {
            return Err(KeystoneError::ClockSkew);
        }
        let deadline = self
            .issued_at
            .checked_add_signed(self.ttl)
            .ok_or(KeystoneError::Expired)?;
        if now >= deadline {
            return Err(KeystoneError::Expired);
        }
        HandoffPayload::decode(&buf)
    }
}

impl HandoffToken {
    /// Seal `payload` for `process_id` under a fresh random launch key,
    /// openable for `ttl`. A ttl outside `(0, MAX_HANDOFF_TTL]` is
    /// `Malformed`; a product longer than `MAX_PRODUCT_LEN` is `FieldTooLong`.
    pub fn seal(payload: &HandoffPayload, process_id: &str, ttl: Duration) -> Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key[..]);
        let blob = Handoff::seal(&key, payload, process_id, ttl)?;
        Ok(Self { key, blob })
    }

    /// Text form: `ksh2.` + base64url(key || nonce || issued_at ms ||
    /// ttl ms || ciphertext), without padding.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new(Vec::with_capacity(
            TOKEN_FIXED_LEN + self.blob.ciphertext.len(),
        ));
        raw.extend_from_slice(&self.key[..]);
        raw.extend_from_slice(&self.blob.nonce);
        raw.extend_from_slice(&self.blob.issued_at.timestamp_millis().to_be_bytes());
        raw.extend_from_slice(&self.blob.ttl.num_milliseconds().to_be_bytes());
        raw.extend_from_slice(&self.blob.ciphertext);
        let mut out = Zeroizing::new(String::with_capacity(
            TOKEN_PREFIX.len() + base64::encoded_len(raw.len(), false).unwrap_or(0),
        ));
        out.push_str(TOKEN_PREFIX);
        URL_SAFE_NO_PAD.encode_string(raw.as_slice(), &mut out);
        out
    }

    /// Parse the text form. A wrong prefix, bad base64, oversize input, or
    /// truncated token is `Malformed`.
    pub fn decode(text: &str) -> Result<Self> {
        let malformed = |what: &str| KeystoneError::Malformed(format!("handoff token: {what}"));
        if text.len() > MAX_TOKEN_LEN {
            return Err(malformed("too long"));
        }
        let body = text
            .strip_prefix(TOKEN_PREFIX)
            .ok_or_else(|| malformed("unknown format"))?;
        let mut raw = Zeroizing::new(Vec::with_capacity(body.len()));
        URL_SAFE_NO_PAD
            .decode_vec(body, &mut raw)
            .map_err(|_| malformed("bad encoding"))?;
        if raw.len() < TOKEN_FIXED_LEN + TAG_LEN {
            return Err(malformed("truncated"));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&raw[..32]);
        let issued_at = DateTime::from_timestamp_millis(i64::from_be_bytes(
            raw[56..64].try_into().expect("8 bytes"),
        ))
        .ok_or_else(|| malformed("bad timestamp"))?;
        let ttl = Duration::try_milliseconds(i64::from_be_bytes(
            raw[64..72].try_into().expect("8 bytes"),
        ))
        .ok_or_else(|| malformed("bad ttl"))?;
        Ok(Self {
            key,
            blob: Handoff {
                nonce: raw[32..56].try_into().expect("24 bytes"),
                issued_at,
                ttl,
                ciphertext: raw[TOKEN_FIXED_LEN..].to_vec(),
            },
        })
    }

    /// Write the text form followed by a newline, then flush.
    pub fn write_to(&self, mut writer: impl Write) -> io::Result<()> {
        writer.write_all(self.encode().as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()
    }

    /// Read one line (up to `\n` or end of input) and decode it. Reads a
    /// byte at a time so nothing past the line is consumed. Read failures
    /// are `Io`; anything `decode` rejects is `Malformed`.
    pub fn read_from(mut reader: impl Read) -> Result<Self> {
        let cap = MAX_TOKEN_LEN + 1;
        let mut line = Zeroizing::new(Vec::with_capacity(cap));
        let mut byte = Zeroizing::new([0u8; 1]);
        loop {
            match reader.read(&mut byte[..]) {
                Ok(0) => break,
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) if line.len() == cap => {
                    return Err(KeystoneError::Malformed("handoff token: too long".into()));
                }
                Ok(_) => line.push(byte[0]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(KeystoneError::Io(e)),
            }
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let text = std::str::from_utf8(&line)
            .map_err(|_| KeystoneError::Malformed("handoff token: not utf-8".into()))?;
        Self::decode(text)
    }

    /// Open the token as `process_id` at the current time. A wrong recipient
    /// or tampered token is `InvalidMac`; a token issued more than 30 s in
    /// the future is `ClockSkew`; one past its ttl is `Expired`.
    pub fn open(self, process_id: &str) -> Result<HandoffPayload> {
        self.blob.open(&self.key, process_id, Utc::now())
    }
}

/// Prints the ciphertext as a length.
impl fmt::Debug for Handoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handoff")
            .field("nonce", &self.nonce)
            .field("issued_at", &self.issued_at)
            .field("ttl", &self.ttl)
            .field(
                "ciphertext",
                &format_args!("[{} bytes]", self.ciphertext.len()),
            )
            .finish()
    }
}

/// Redacts the handoff secret.
impl fmt::Debug for HandoffPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandoffPayload")
            .field("parent_session_id", &self.parent_session_id)
            .field("handoff_id", &self.handoff_id)
            .field("handoff_secret", &"[redacted]")
            .field("product", &self.product)
            .field("expires_at", &self.expires_at)
            .field("server_offset_millis", &self.server_offset_millis)
            .finish()
    }
}

/// Redacts the launch key.
impl fmt::Debug for HandoffToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandoffToken")
            .field("key", &"[redacted]")
            .field("blob", &self.blob)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];
    const PROCESS: &str = "game.exe";

    fn payload() -> HandoffPayload {
        HandoffPayload {
            parent_session_id: Uuid::new_v4(),
            handoff_id: [0x11; 32],
            handoff_secret: [0xAB; 32],
            product: "prod".into(),
            expires_at: DateTime::from_timestamp_millis(1_900_000_000_123).unwrap(),
            server_offset_millis: -1_250,
        }
    }

    fn seal() -> Handoff {
        Handoff::seal(&KEY, &payload(), PROCESS, Duration::seconds(60)).unwrap()
    }

    #[test]
    fn seal_open_round_trips_every_field() {
        let sent = payload();
        let blob = Handoff::seal(&KEY, &sent, PROCESS, Duration::seconds(60)).unwrap();
        let got = blob.open(&KEY, PROCESS, Utc::now()).unwrap();
        assert_eq!(got.parent_session_id, sent.parent_session_id);
        assert_eq!(got.handoff_id, sent.handoff_id);
        assert_eq!(got.handoff_secret, sent.handoff_secret);
        assert_eq!(got.product, sent.product);
        assert_eq!(got.expires_at, sent.expires_at);
        assert_eq!(got.server_offset_millis, sent.server_offset_millis);
    }

    #[test]
    fn wrong_key_or_recipient_fails() {
        let blob = seal();
        assert!(matches!(
            blob.open(&[0x99; 32], PROCESS, Utc::now()),
            Err(KeystoneError::InvalidMac)
        ));
        assert!(matches!(
            blob.open(&KEY, "other.exe", Utc::now()),
            Err(KeystoneError::InvalidMac)
        ));
    }

    #[test]
    fn freshness_window_is_enforced() {
        let blob = seal();
        assert!(matches!(
            blob.open(&KEY, PROCESS, blob.issued_at + Duration::seconds(60)),
            Err(KeystoneError::Expired)
        ));
        assert!(matches!(
            blob.open(&KEY, PROCESS, blob.issued_at - Duration::seconds(31)),
            Err(KeystoneError::ClockSkew)
        ));
    }

    #[test]
    fn tampering_fails_the_tag() {
        let mut blob = seal();
        blob.ciphertext[0] ^= 1;
        assert!(matches!(
            blob.open(&KEY, PROCESS, Utc::now()),
            Err(KeystoneError::InvalidMac)
        ));
        // The window is associated data: stretching it breaks the tag.
        let mut blob = seal();
        blob.ttl = Duration::days(1);
        assert!(matches!(
            blob.open(&KEY, PROCESS, Utc::now()),
            Err(KeystoneError::InvalidMac)
        ));
    }

    #[test]
    fn seal_rejects_ttl_outside_bounds() {
        for ttl in [
            Duration::zero(),
            Duration::seconds(-1),
            MAX_HANDOFF_TTL + Duration::milliseconds(1),
        ] {
            assert!(matches!(
                Handoff::seal(&KEY, &payload(), PROCESS, ttl),
                Err(KeystoneError::Malformed(_))
            ));
        }
        Handoff::seal(&KEY, &payload(), PROCESS, MAX_HANDOFF_TTL).unwrap();
    }

    #[test]
    fn overflowing_ttl_expires_instead_of_panicking() {
        // Forged with a valid tag, since the AAD covers the same ttl.
        let nonce = XChaCha20Poly1305::generate_nonce(&mut rand::thread_rng());
        let nonce_bytes: [u8; NONCE_LEN] = nonce.into();
        let issued_at = Utc::now();
        let mut buf = payload().encode();
        cipher(&KEY, &nonce_bytes, PROCESS)
            .encrypt_in_place(&nonce, &aad(issued_at, Duration::MAX), &mut *buf)
            .unwrap();
        let blob = Handoff {
            nonce: nonce_bytes,
            issued_at,
            ttl: Duration::MAX,
            ciphertext: buf.to_vec(),
        };
        assert!(matches!(
            blob.open(&KEY, PROCESS, Utc::now()),
            Err(KeystoneError::Expired)
        ));
    }

    #[test]
    fn token_text_round_trips_and_binds_process_id() {
        let sent = payload();
        let token = HandoffToken::seal(&sent, PROCESS, Duration::seconds(60)).unwrap();
        let text = token.encode();
        assert!(text.starts_with("ksh2."));

        let got = HandoffToken::decode(&text).unwrap().open(PROCESS).unwrap();
        assert_eq!(got.handoff_id, sent.handoff_id);
        assert_eq!(got.handoff_secret, sent.handoff_secret);

        assert!(matches!(
            HandoffToken::decode(&text).unwrap().open("other.exe"),
            Err(KeystoneError::InvalidMac)
        ));
    }

    #[test]
    fn token_read_failure_is_io_not_malformed() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
        match HandoffToken::read_from(Broken) {
            Err(KeystoneError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn token_stream_reads_exactly_one_line() {
        let token = HandoffToken::seal(&payload(), PROCESS, Duration::seconds(60)).unwrap();
        let mut stream = Vec::new();
        token.write_to(&mut stream).unwrap();
        stream.extend_from_slice(b"trailing input");

        let mut reader = io::Cursor::new(stream);
        let got = HandoffToken::read_from(&mut reader).unwrap();
        assert_eq!(got.open(PROCESS).unwrap().handoff_secret, [0xAB; 32]);
        let mut rest = String::new();
        reader.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "trailing input");
    }

    #[test]
    fn token_decode_rejects_foreign_or_truncated_text() {
        let token = HandoffToken::seal(&payload(), PROCESS, Duration::seconds(60)).unwrap();
        let text = token.encode();
        for bad in [
            text.replacen("ksh2.", "ksh1.", 1),
            text[..40].to_string(),
            format!("{}!", &text[..text.len() - 1]),
            "x".repeat(MAX_TOKEN_LEN + 1),
        ] {
            assert!(matches!(
                HandoffToken::decode(&bad),
                Err(KeystoneError::Malformed(_))
            ));
        }
    }

    #[test]
    fn debug_redacts_secrets() {
        let token = HandoffToken::seal(&payload(), PROCESS, Duration::seconds(60)).unwrap();
        let secret_bytes = format!("{:?}", [0xABu8; 32]);
        assert!(!format!("{:?}", payload()).contains(&secret_bytes));
        assert!(!format!("{token:?}").contains(&format!("{:?}", *token.key)));
    }
}
