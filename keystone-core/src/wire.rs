//! The HTTP contract between keystone servers and clients: protocol
//! version, envelope scopes, field caps, error codes, request and
//! response bodies, and the MAC contexts each request binds.

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{KeystoneError, Result};
use crate::lease::{DeadReason, Lease};
use crate::manifest::{FeatureGrant, SignedManifest};
use crate::payload::{KeyWrap, valid_segment};

/// Wire protocol version this build speaks.
pub const PROTOCOL_VERSION: u16 = 2;
/// Header every request carries with [`PROTOCOL_VERSION`] as its value.
pub const PROTOCOL_HEADER: &str = "keystone-protocol";

/// Header carrying the admin token on admin-listener requests.
pub const ADMIN_TOKEN_HEADER: &str = "keystone-admin-token";
/// Header carrying the build id of an artifact being published.
pub const BUILD_ID_HEADER: &str = "keystone-build-id";

/// Audience of the exchange, handoff, and heartbeat envelopes.
pub const AUDIENCE_CLIENT: &str = "keystone-client";
/// Audience of the attest and payload-fetch envelopes.
pub const AUDIENCE_APP: &str = "keystone-app";

/// Operation of the exchange envelope.
pub const OP_EXCHANGE: &str = "session.exchange";
/// Operation of the attest envelope.
pub const OP_ATTEST: &str = "session.attest";
/// Operation of the heartbeat envelope.
pub const OP_HEARTBEAT: &str = "session.heartbeat";
/// Operation of the payload manifest envelope.
pub const OP_PAYLOAD_FETCH: &str = "payload.fetch";
/// Operation of the handoff envelope.
pub const OP_HANDOFF: &str = "handoff";

/// Longest accepted account name, in bytes.
pub const MAX_ACCOUNT_LEN: usize = 128;
/// Longest accepted account secret, in bytes.
pub const MAX_SECRET_LEN: usize = 1024;
/// Shortest admin token a server accepts as configuration, in characters.
pub const MIN_ADMIN_TOKEN_LEN: usize = 32;
/// Longest accepted admin token, in bytes.
pub const MAX_ADMIN_TOKEN_BYTES: usize = 1024;
/// Longest accepted product name, in bytes.
pub const MAX_PRODUCT_LEN: usize = 64;
/// Longest accepted version string, in bytes.
pub const MAX_VERSION_LEN: usize = 64;
/// Longest accepted process identity, in bytes.
pub const MAX_PROCESS_ID_LEN: usize = 128;
/// Longest accepted build id, in bytes.
pub const MAX_BUILD_ID_LEN: usize = 64;
/// Upper bound on a handoff's lifetime; longer requests are clamped.
pub const MAX_HANDOFF_TTL: Duration = Duration::minutes(5);
/// Handoff lifetime used when the caller has no preference.
pub const DEFAULT_HANDOFF_TTL: Duration = Duration::seconds(60);

/// Request paths, relative to the server's base URL.
pub mod paths {
    /// `POST`: [`super::ExchangeRequest`].
    pub const EXCHANGE: &str = "/exchange";
    /// `POST`: [`super::HandoffRequest`].
    pub const HANDOFF: &str = "/handoff";
    /// `POST`: [`super::AttestRequest`].
    pub const ATTEST: &str = "/attest";
    /// `POST`: [`super::HeartbeatRequest`].
    pub const HEARTBEAT: &str = "/heartbeat";
    /// `POST`: [`super::PayloadRequest`]; also the prefix of [`download`].
    pub const PAYLOAD: &str = "/payload";
    /// `POST` on the admin listener: [`super::RevokeRequest`].
    pub const REVOKE: &str = "/revoke";

    /// `GET` path of a sealed artifact, authorized by a
    /// [`super::DownloadAuthorization`] header. Callers pass values that
    /// passed [`super::validate_release`].
    pub fn download(product: &str, version: &str) -> String {
        format!("{PAYLOAD}/{product}/{version}")
    }

    /// Admin-listener path of a release's sealed artifact, for publishing.
    /// Callers pass values that passed [`super::validate_release`].
    pub fn artifact(product: &str, version: &str) -> String {
        format!("/artifacts/{product}/{version}")
    }
}

/// Serde adapter for `DateTime<Utc>` as integer epoch milliseconds.
/// Deserialized values are always millisecond-aligned, so a timestamp
/// that is signed or MAC'd at millisecond precision equals its wire form.
pub mod millis {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    /// Serialize as epoch milliseconds.
    pub fn serialize<S: Serializer>(value: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(value.timestamp_millis())
    }

    /// Deserialize from epoch milliseconds; out-of-range values fail.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let ms = i64::deserialize(d)?;
        DateTime::from_timestamp_millis(ms)
            .ok_or_else(|| D::Error::custom("timestamp out of range"))
    }
}

/// Serde adapter for `chrono::Duration` as integer milliseconds.
/// Deserialized values are always millisecond-aligned.
pub mod duration_millis {
    use chrono::Duration;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    /// Serialize as whole milliseconds; sub-millisecond parts are dropped.
    pub fn serialize<S: Serializer>(value: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(value.num_milliseconds())
    }

    /// Deserialize from milliseconds; out-of-range values fail.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let ms = i64::deserialize(d)?;
        Duration::try_milliseconds(ms).ok_or_else(|| D::Error::custom("duration out of range"))
    }
}

/// Machine-readable reason carried by every non-2xx keystone response.
/// Codes this build does not know deserialize as [`ErrorCode::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Account or secret did not authenticate.
    InvalidCredentials,
    /// The request MAC did not verify.
    InvalidMac,
    /// The request timestamp is outside the freshness window.
    StaleRequest,
    /// The request nonce was already used.
    Replay,
    /// A rate limit was hit.
    RateLimited,
    /// The server does not know the session.
    UnknownSession,
    /// The session was revoked.
    SessionRevoked,
    /// The session's lease or grant expired.
    SessionExpired,
    /// The session's grace period ran out.
    GraceExhausted,
    /// The account holds no grant for the product.
    NoEntitlement,
    /// The request names a product other than the session's.
    WrongProduct,
    /// The handoff is unknown, spent, expired, or bound elsewhere.
    HandoffInvalid,
    /// No artifact exists for the product and version.
    ArtifactNotFound,
    /// The stored artifact or its sidecars are unusable.
    ArtifactInvalid,
    /// A backing service is down.
    BackendUnavailable,
    /// Missing or unsupported protocol header.
    UnsupportedProtocol,
    /// The request failed validation.
    BadRequest,
    /// The caller is not allowed to perform this operation.
    Forbidden,
    /// The key id is the server's active signing key and cannot be revoked.
    ActiveSigningKey,
    /// The target already exists and cannot be replaced, e.g. a published release.
    Conflict,
    /// A code this build does not recognize.
    Unknown,
}

/// What a client must do with a session after an [`ErrorCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Retry later; the session survives and grace may start.
    Transient,
    /// The session is over for the given reason.
    Kill(DeadReason),
    /// The request itself was wrong; the session is untouched.
    RequestError,
}

impl ErrorCode {
    /// The snake_case wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidCredentials => "invalid_credentials",
            ErrorCode::InvalidMac => "invalid_mac",
            ErrorCode::StaleRequest => "stale_request",
            ErrorCode::Replay => "replay",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::UnknownSession => "unknown_session",
            ErrorCode::SessionRevoked => "session_revoked",
            ErrorCode::SessionExpired => "session_expired",
            ErrorCode::GraceExhausted => "grace_exhausted",
            ErrorCode::NoEntitlement => "no_entitlement",
            ErrorCode::WrongProduct => "wrong_product",
            ErrorCode::HandoffInvalid => "handoff_invalid",
            ErrorCode::ArtifactNotFound => "artifact_not_found",
            ErrorCode::ArtifactInvalid => "artifact_invalid",
            ErrorCode::BackendUnavailable => "backend_unavailable",
            ErrorCode::UnsupportedProtocol => "unsupported_protocol",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Forbidden => "forbidden",
            ErrorCode::ActiveSigningKey => "active_signing_key",
            ErrorCode::Conflict => "conflict",
            ErrorCode::Unknown => "unknown",
        }
    }

    /// Parse a wire string; anything unrecognized is [`ErrorCode::Unknown`].
    pub fn from_wire(s: &str) -> Self {
        match s {
            "invalid_credentials" => ErrorCode::InvalidCredentials,
            "invalid_mac" => ErrorCode::InvalidMac,
            "stale_request" => ErrorCode::StaleRequest,
            "replay" => ErrorCode::Replay,
            "rate_limited" => ErrorCode::RateLimited,
            "unknown_session" => ErrorCode::UnknownSession,
            "session_revoked" => ErrorCode::SessionRevoked,
            "session_expired" => ErrorCode::SessionExpired,
            "grace_exhausted" => ErrorCode::GraceExhausted,
            "no_entitlement" => ErrorCode::NoEntitlement,
            "wrong_product" => ErrorCode::WrongProduct,
            "handoff_invalid" => ErrorCode::HandoffInvalid,
            "artifact_not_found" => ErrorCode::ArtifactNotFound,
            "artifact_invalid" => ErrorCode::ArtifactInvalid,
            "backend_unavailable" => ErrorCode::BackendUnavailable,
            "unsupported_protocol" => ErrorCode::UnsupportedProtocol,
            "bad_request" => ErrorCode::BadRequest,
            "forbidden" => ErrorCode::Forbidden,
            "active_signing_key" => ErrorCode::ActiveSigningKey,
            "conflict" => ErrorCode::Conflict,
            _ => ErrorCode::Unknown,
        }
    }

    /// The single mapping from a server code to the client's session
    /// verdict. Unknown codes are transient so a newer server can never
    /// kill an older client's session by accident.
    pub fn verdict(self) -> Verdict {
        match self {
            ErrorCode::StaleRequest
            | ErrorCode::Replay
            | ErrorCode::RateLimited
            | ErrorCode::ArtifactNotFound
            | ErrorCode::BackendUnavailable
            | ErrorCode::Unknown => Verdict::Transient,
            ErrorCode::InvalidMac => Verdict::Kill(DeadReason::Rejected),
            ErrorCode::UnknownSession => Verdict::Kill(DeadReason::UnknownSession),
            ErrorCode::SessionRevoked | ErrorCode::NoEntitlement => {
                Verdict::Kill(DeadReason::Revoked)
            }
            ErrorCode::SessionExpired => Verdict::Kill(DeadReason::Expired),
            ErrorCode::GraceExhausted => Verdict::Kill(DeadReason::GraceExhausted),
            ErrorCode::InvalidCredentials
            | ErrorCode::WrongProduct
            | ErrorCode::HandoffInvalid
            | ErrorCode::ArtifactInvalid
            | ErrorCode::UnsupportedProtocol
            | ErrorCode::BadRequest
            | ErrorCode::Forbidden
            | ErrorCode::ActiveSigningKey
            | ErrorCode::Conflict => Verdict::RequestError,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct CodeVisitor;
        impl serde::de::Visitor<'_> for CodeVisitor {
            type Value = ErrorCode;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an error code string")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<ErrorCode, E> {
                Ok(ErrorCode::from_wire(v))
            }
        }
        d.deserialize_str(CodeVisitor)
    }
}

/// Body of every non-2xx keystone response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// What went wrong, for machines.
    pub code: ErrorCode,
    /// What went wrong, for people; never carries secrets.
    pub message: String,
}

/// `POST /exchange`: credentials for a new session.
#[derive(Clone, Serialize, Deserialize)]
pub struct ExchangeRequest {
    /// Account name.
    pub account: String,
    /// Account secret.
    pub secret: Zeroizing<String>,
    /// Product the session is for.
    pub product: String,
    /// Hardware fingerprint; an anomaly signal, not a gate.
    pub hwid: [u8; 32],
    /// Challenge nonce the exchange envelope must echo.
    pub challenge: [u8; 32],
}

impl ExchangeRequest {
    /// Enforce the field caps; `product` must also be a valid path segment.
    pub fn validate(&self) -> Result<()> {
        required("account", &self.account, MAX_ACCOUNT_LEN)?;
        required("secret", &self.secret, MAX_SECRET_LEN)?;
        segment("product", &self.product, MAX_PRODUCT_LEN)
    }
}

impl fmt::Debug for ExchangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeRequest")
            .field("account", &self.account)
            .field("secret", &"[redacted]")
            .field("product", &self.product)
            .finish_non_exhaustive()
    }
}

/// Signed body of the exchange envelope; the only place a loader session
/// key crosses the wire.
#[derive(Clone, Serialize, Deserialize)]
pub struct ExchangeBody {
    /// The new session.
    pub session_id: Uuid,
    /// Key for the session's request MACs.
    pub session_key: Zeroizing<[u8; 32]>,
    /// The first lease.
    pub lease: Lease,
    /// Feature grants of the live entitlement.
    pub features: Vec<FeatureGrant>,
    /// Server clock at issue.
    #[serde(with = "millis")]
    pub server_time: DateTime<Utc>,
    /// Issuer key ids the client must stop trusting.
    pub revoked_key_ids: Vec<u8>,
}

impl fmt::Debug for ExchangeBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeBody")
            .field("session_id", &self.session_id)
            .field("session_key", &"[redacted]")
            .field("lease", &self.lease)
            .field("features", &self.features)
            .field("server_time", &self.server_time)
            .field("revoked_key_ids", &self.revoked_key_ids)
            .finish()
    }
}

/// `POST /handoff`: mint a single-use handoff for a child process. MAC'd
/// under the loader session key with [`mac_context::handoff`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffRequest {
    /// The loader session.
    pub session_id: Uuid,
    /// Request nonce; also the envelope challenge.
    pub nonce: [u8; 32],
    /// Requester clock at mint time.
    #[serde(with = "millis")]
    pub issued_at: DateTime<Utc>,
    /// Identity the child process will attest under.
    pub process_id: String,
    /// Requested lifetime; the server clamps to [`MAX_HANDOFF_TTL`].
    pub ttl_millis: u64,
    /// Request MAC.
    pub mac: [u8; 32],
}

impl HandoffRequest {
    /// Enforce the field caps; a zero TTL is `Malformed`.
    pub fn validate(&self) -> Result<()> {
        required("process_id", &self.process_id, MAX_PROCESS_ID_LEN)?;
        if self.ttl_millis == 0 {
            return Err(KeystoneError::Malformed("ttl_millis is zero".into()));
        }
        Ok(())
    }

    /// The requested lifetime clamped to [`MAX_HANDOFF_TTL`].
    pub fn ttl(&self) -> Duration {
        let max = MAX_HANDOFF_TTL.num_milliseconds() as u64;
        Duration::milliseconds(self.ttl_millis.min(max) as i64)
    }
}

/// Signed body of the handoff envelope.
#[derive(Clone, Serialize, Deserialize)]
pub struct HandoffBody {
    /// Identifies the handoff at attest time.
    pub handoff_id: [u8; 32],
    /// Keys the attest MAC and the child session key wrap.
    pub handoff_secret: Zeroizing<[u8; 32]>,
    /// Last instant the handoff can be attested.
    #[serde(with = "millis")]
    pub expires_at: DateTime<Utc>,
    /// Server clock at issue.
    #[serde(with = "millis")]
    pub server_time: DateTime<Utc>,
    /// Issuer key ids the client must stop trusting.
    pub revoked_key_ids: Vec<u8>,
}

impl fmt::Debug for HandoffBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandoffBody")
            .field("handoff_id", &self.handoff_id)
            .field("handoff_secret", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("server_time", &self.server_time)
            .field("revoked_key_ids", &self.revoked_key_ids)
            .finish()
    }
}

/// `POST /attest`: redeem a handoff for a child session. MAC'd under the
/// handoff secret with the parent session id and [`mac_context::attest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestRequest {
    /// The loader session that minted the handoff.
    pub parent_session_id: Uuid,
    /// The handoff being redeemed.
    pub handoff_id: [u8; 32],
    /// Request nonce; also the envelope challenge and the wrap-key salt.
    pub challenge: [u8; 32],
    /// Requester clock at mint time.
    #[serde(with = "millis")]
    pub issued_at: DateTime<Utc>,
    /// Identity the handoff was minted for.
    pub process_id: String,
    /// Request MAC.
    pub mac: [u8; 32],
}

impl AttestRequest {
    /// Enforce the field caps.
    pub fn validate(&self) -> Result<()> {
        required("process_id", &self.process_id, MAX_PROCESS_ID_LEN)
    }
}

/// Signed body of the attest envelope. The child session key is wrapped
/// under [`crate::handoff_wrap_key`]`(handoff_secret, challenge)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestBody {
    /// The new child session.
    pub session_id: Uuid,
    /// The child session key, wrapped.
    pub session_key_wrap: KeyWrap,
    /// The child's first lease.
    pub lease: Lease,
    /// Feature grants of the live entitlement.
    pub features: Vec<FeatureGrant>,
    /// Server clock at issue.
    #[serde(with = "millis")]
    pub server_time: DateTime<Utc>,
    /// Issuer key ids the client must stop trusting.
    pub revoked_key_ids: Vec<u8>,
}

/// `POST /heartbeat`: renew the lease. MAC'd with [`mac_context::heartbeat`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    /// The session.
    pub session_id: Uuid,
    /// Request nonce; also the envelope challenge.
    pub nonce: [u8; 32],
    /// Requester clock at mint time.
    #[serde(with = "millis")]
    pub issued_at: DateTime<Utc>,
    /// Request MAC.
    pub mac: [u8; 32],
}

impl HeartbeatRequest {
    /// Enforce the field caps; a heartbeat has no variable-length fields.
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Signed body of the heartbeat envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseBody {
    /// The renewed lease.
    pub lease: Lease,
    /// Feature grants of the live entitlement.
    pub features: Vec<FeatureGrant>,
    /// Server clock at issue.
    #[serde(with = "millis")]
    pub server_time: DateTime<Utc>,
    /// Issuer key ids the client must stop trusting.
    pub revoked_key_ids: Vec<u8>,
}

/// `POST /payload`: fetch the manifest and wrapped artifact key. MAC'd
/// with [`mac_context::payload`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadRequest {
    /// The session.
    pub session_id: Uuid,
    /// Product; must equal the session's.
    pub product: String,
    /// Release version.
    pub version: String,
    /// Request nonce; also the envelope challenge and the wrap-key salt.
    pub nonce: [u8; 32],
    /// Requester clock at mint time.
    #[serde(with = "millis")]
    pub issued_at: DateTime<Utc>,
    /// Request MAC.
    pub mac: [u8; 32],
}

impl PayloadRequest {
    /// Enforce the field caps; product and version must pass [`validate_release`].
    pub fn validate(&self) -> Result<()> {
        validate_release(&self.product, &self.version)
    }
}

/// Signed body of the payload envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadBody {
    /// The signed manifest for the release.
    pub manifest: SignedManifest,
    /// The artifact key wrapped under [`crate::payload_wrap_key`].
    pub payload_key_wrap: KeyWrap,
    /// Server clock at issue.
    #[serde(with = "millis")]
    pub server_time: DateTime<Utc>,
    /// Issuer key ids the client must stop trusting.
    pub revoked_key_ids: Vec<u8>,
}

/// The `Authorization` header value of a sealed artifact download:
/// `Keystone <session_id>:<nonce hex>:<issued_at ms>:<mac hex>`. The MAC
/// is a request MAC under the session key with [`mac_context::download`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadAuthorization {
    /// The session.
    pub session_id: Uuid,
    /// Request nonce.
    pub nonce: [u8; 32],
    /// Requester clock at mint time; millisecond precision on the wire.
    pub issued_at: DateTime<Utc>,
    /// Request MAC.
    pub mac: [u8; 32],
}

impl DownloadAuthorization {
    const SCHEME: &'static str = "Keystone ";

    /// The header value.
    pub fn encode(&self) -> String {
        format!(
            "{}{}:{}:{}:{}",
            Self::SCHEME,
            self.session_id.hyphenated(),
            hex::encode(self.nonce),
            self.issued_at.timestamp_millis(),
            hex::encode(self.mac)
        )
    }

    /// Parse a header value; any deviation from the format is `Malformed`.
    /// The parsed `issued_at` is millisecond-aligned.
    pub fn parse(value: &str) -> Result<Self> {
        let bad = || KeystoneError::Malformed("download authorization".into());
        let mut parts = value.strip_prefix(Self::SCHEME).ok_or_else(bad)?.split(':');
        let mut next = || parts.next().ok_or_else(bad);
        let session_id = Uuid::try_parse(next()?).map_err(|_| bad())?;
        let nonce = hex32(next()?).ok_or_else(bad)?;
        let issued_at = next()?
            .parse::<i64>()
            .ok()
            .and_then(DateTime::from_timestamp_millis)
            .ok_or_else(bad)?;
        let mac = hex32(next()?).ok_or_else(bad)?;
        if parts.next().is_some() {
            return Err(bad());
        }
        Ok(Self {
            session_id,
            nonce,
            issued_at,
            mac,
        })
    }
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).ok()?;
    Some(out)
}

/// What a revocation targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeTarget {
    /// One session and its children.
    Session(Uuid),
    /// Every session of an account.
    Account(String),
    /// An issuer key id; every session dies.
    KeyId(u8),
}

/// `POST /revoke` on the admin listener.
#[derive(Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    /// Operator credential.
    pub admin_token: Zeroizing<String>,
    /// What to revoke.
    pub target: RevokeTarget,
}

impl RevokeRequest {
    /// Enforce the field caps.
    pub fn validate(&self) -> Result<()> {
        required("admin_token", &self.admin_token, MAX_ADMIN_TOKEN_BYTES)?;
        if let RevokeTarget::Account(account) = &self.target {
            required("account", account, MAX_ACCOUNT_LEN)?;
        }
        Ok(())
    }
}

impl fmt::Debug for RevokeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevokeRequest")
            .field("admin_token", &"[redacted]")
            .field("target", &self.target)
            .finish()
    }
}

/// Response to a revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeBody {
    /// Number of sessions killed.
    pub revoked: u64,
}

/// A published release as the server stored it: the admin artifact
/// publish endpoint's response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishBody {
    /// Product name.
    pub product: String,
    /// Release version.
    pub version: String,
    /// Hex sha256 of the plaintext payload.
    pub sha256: String,
    /// Build id stamped into manifests of this release.
    pub build_id: String,
}

/// Canonical `context` bytes for [`crate::RequestBinding`], one function
/// per MAC'd operation. Every field is length-prefixed behind an
/// operation label, so a tag for one operation or argument set never
/// verifies for another.
pub mod mac_context {
    /// `POST /heartbeat`.
    pub fn heartbeat() -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 9);
        push(&mut buf, b"heartbeat");
        buf
    }

    /// `POST /handoff`, binding the child identity and requested TTL.
    pub fn handoff(process_id: &str, ttl_millis: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 7 + 4 + process_id.len() + 8);
        push(&mut buf, b"handoff");
        push(&mut buf, process_id.as_bytes());
        buf.extend_from_slice(&ttl_millis.to_be_bytes());
        buf
    }

    /// `POST /attest`, binding the handoff and the child identity.
    pub fn attest(handoff_id: &[u8; 32], process_id: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 6 + 32 + 4 + process_id.len());
        push(&mut buf, b"attest");
        buf.extend_from_slice(handoff_id);
        push(&mut buf, process_id.as_bytes());
        buf
    }

    /// `POST /payload`, binding product and version.
    pub fn payload(product: &str, version: &str) -> Vec<u8> {
        artifact(b"payload.fetch", product, version)
    }

    /// `GET /payload/{product}/{version}`, binding product and version.
    pub fn download(product: &str, version: &str) -> Vec<u8> {
        artifact(b"payload.download", product, version)
    }

    fn artifact(label: &[u8], product: &str, version: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + label.len() + product.len() + version.len());
        push(&mut buf, label);
        push(&mut buf, product.as_bytes());
        push(&mut buf, version.as_bytes());
        buf
    }

    fn push(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(bytes);
    }
}

/// Check a build id: non-empty (`Malformed`), within [`MAX_BUILD_ID_LEN`]
/// (`FieldTooLong`), and only ASCII alphanumerics, `.`, `_`, `-` (`Malformed`).
pub fn validate_build_id(build_id: &str) -> Result<()> {
    required("build_id", build_id, MAX_BUILD_ID_LEN)?;
    if !build_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(KeystoneError::Malformed("invalid build_id".into()));
    }
    Ok(())
}

/// Check a product/version pair used in a path or artifact layout: each
/// non-empty (`Malformed`), within [`MAX_PRODUCT_LEN`] / [`MAX_VERSION_LEN`]
/// (`FieldTooLong`), and a [`valid_segment`] (`Malformed`).
pub fn validate_release(product: &str, version: &str) -> Result<()> {
    segment("product", product, MAX_PRODUCT_LEN)?;
    segment("version", version, MAX_VERSION_LEN)
}

fn required(field: &'static str, value: &str, max: usize) -> Result<()> {
    if value.is_empty() {
        return Err(KeystoneError::Malformed(format!("{field} is empty")));
    }
    if value.len() > max {
        return Err(KeystoneError::FieldTooLong(field));
    }
    Ok(())
}

fn segment(field: &'static str, value: &str, max: usize) -> Result<()> {
    required(field, value, max)?;
    if !valid_segment(value) {
        return Err(KeystoneError::Malformed(format!("invalid {field}")));
    }
    Ok(())
}
