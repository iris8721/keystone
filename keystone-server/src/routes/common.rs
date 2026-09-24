//! Pieces every route shares: error responses, extractors, rate-limit
//! keys, the session gate, and live grant resolution.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};

use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Request};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use keystone_core::wire::{ErrorBody, ErrorCode};
use keystone_core::{
    DeadReason, Entitlement, Envelope, FeatureGrant, IssueSpec, KeystoneError, RequestBinding,
    check_request_freshness, request_nonce_expiry, verify_request_mac,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::error::ServerError;
use crate::state::{AppState, CAS_ATTEMPTS};
use crate::store::SessionRecord;
use crate::tls::PeerCertificates;

/// A keystone denial: a wire [`ErrorCode`] plus a human message, rendered
/// as an [`ErrorBody`] with the code's status.
#[derive(Debug)]
pub(crate) struct ApiError {
    code: ErrorCode,
    status: StatusCode,
    message: Cow<'static, str>,
}

impl ApiError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            status: status_for(code),
            message: message.into(),
        }
    }

    pub(crate) fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    pub(crate) fn bad_request(e: KeystoneError) -> Self {
        Self::new(ErrorCode::BadRequest, e.to_string())
    }

    pub(crate) fn backend(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "backend failure");
        Self::new(ErrorCode::BackendUnavailable, "backend unavailable")
    }

    pub(crate) fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "internal error");
        Self::new(ErrorCode::Unknown, "internal error")
    }

    pub(crate) fn from_server(e: ServerError) -> Self {
        match e {
            ServerError::ActiveKeyRevoked(id) => Self::new(
                ErrorCode::ActiveSigningKey,
                format!("key id {id} is the active signing key"),
            ),
            ServerError::Store(e) | ServerError::Revocations(e) => Self::backend(e),
            other => Self::internal(other),
        }
    }

    fn dead(reason: DeadReason) -> Self {
        match reason {
            DeadReason::Rejected | DeadReason::Revoked => {
                Self::new(ErrorCode::SessionRevoked, "session revoked")
            }
            DeadReason::UnknownSession => Self::unknown_session(),
            DeadReason::Expired => Self::new(ErrorCode::SessionExpired, "session expired"),
            DeadReason::GraceExhausted => {
                Self::new(ErrorCode::GraceExhausted, "grace period exhausted")
            }
        }
    }

    pub(crate) fn unknown_session() -> Self {
        Self::new(ErrorCode::UnknownSession, "unknown session")
    }

    pub(crate) fn rate_limited() -> Self {
        Self::new(ErrorCode::RateLimited, "rate limited")
    }
}

/// The one mapping from wire code to HTTP status.
pub(crate) fn status_for(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::InvalidCredentials | ErrorCode::InvalidMac | ErrorCode::StaleRequest => {
            StatusCode::UNAUTHORIZED
        }
        ErrorCode::Replay | ErrorCode::ActiveSigningKey | ErrorCode::Conflict => {
            StatusCode::CONFLICT
        }
        ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::UnknownSession | ErrorCode::ArtifactNotFound => StatusCode::NOT_FOUND,
        ErrorCode::SessionRevoked
        | ErrorCode::NoEntitlement
        | ErrorCode::WrongProduct
        | ErrorCode::Forbidden => StatusCode::FORBIDDEN,
        ErrorCode::SessionExpired | ErrorCode::GraceExhausted => StatusCode::GONE,
        ErrorCode::HandoffInvalid => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::BackendUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::UnsupportedProtocol | ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                code: self.code,
                message: self.message.into_owned(),
            }),
        )
            .into_response()
    }
}

/// JSON body extractor whose rejections are keystone `bad_request` bodies
/// (413 when over the body limit).
pub(crate) struct WireJson<T>(pub T);

#[axum::async_trait]
impl<S, T> FromRequest<S> for WireJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(json_rejection(rejection)),
        }
    }
}

fn json_rejection(rejection: JsonRejection) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, rejection.body_text()).with_status(rejection.status())
}

/// Who is on the other end: source address and, over mTLS, the client
/// certificate chain. Extraction fails closed with 500 `unknown` when the
/// transport did not supply the address (`ConnectInfo<SocketAddr>`), or did
/// not supply certificates while the state requires them.
pub(crate) struct Peer {
    pub(crate) ip: IpAddr,
    pub(crate) certs: Option<PeerCertificates>,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for Peer {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let Ok(ConnectInfo(addr)) =
            ConnectInfo::<SocketAddr>::from_request_parts(parts, state).await
        else {
            return Err(ApiError::internal(
                "request without ConnectInfo<SocketAddr>; serve the router with connect info",
            ));
        };
        let certs = parts
            .extensions
            .get::<PeerCertificates>()
            .filter(|c| !c.is_empty())
            .cloned();
        if certs.is_none() && state.inner.require_client_certificates {
            return Err(ApiError::internal(
                "client certificates required but none attached; serve through PeerCertAcceptor",
            ));
        }
        Ok(Self {
            ip: addr.ip(),
            certs,
        })
    }
}

impl Peer {
    pub(crate) fn cert_sha256(&self) -> Option<[u8; 32]> {
        self.certs.as_ref().and_then(PeerCertificates::leaf_sha256)
    }

    /// Rate-limit key for whoever is presenting: the leaf certificate under
    /// mTLS, else the client address.
    pub(crate) fn presenter_key(&self, route: &str) -> String {
        match self.cert_sha256() {
            Some(leaf) => format!("{route}:cert:{}", hex::encode(leaf)),
            None => ip_key(route, self.ip),
        }
    }

    /// Whether the presented certificate may act for `account`: under mTLS
    /// the leaf CN must equal the account, and an account pin must match the
    /// leaf exactly; without a client certificate only unpinned accounts pass.
    pub(crate) async fn may_act_for(
        &self,
        state: &AppState,
        account: &str,
    ) -> Result<bool, ApiError> {
        let pinned = state
            .inner
            .entitlements
            .cert_sha256(account)
            .await
            .map_err(ApiError::backend)?;
        let Some(certs) = &self.certs else {
            return Ok(pinned.is_none());
        };
        if certs.leaf_common_name().as_deref() != Some(account) {
            return Ok(false);
        }
        Ok(match pinned {
            Some(pin) => certs
                .leaf_sha256()
                .is_some_and(|leaf| bool::from(leaf.ct_eq(&pin))),
            None => true,
        })
    }
}

/// Rate-limit key for a client address. IPv6 clients are bucketed per /64
/// so one host cannot rotate through its own prefix.
pub(crate) fn ip_key(route: &str, ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => format!("{route}:ip4:{v4}"),
        IpAddr::V6(v6) => format!("{route}:ip6:{:016x}", u128::from(v6) >> 64),
    }
}

/// Charge `key`; over the limit is 429 `rate_limited`.
pub(crate) async fn limit(state: &AppState, key: &str, per_window: u32) -> Result<(), ApiError> {
    if state
        .inner
        .limiter
        .check(key, per_window, state.inner.rate_limits.window)
        .await
    {
        Ok(())
    } else {
        Err(ApiError::rate_limited())
    }
}

/// Server clock at millisecond precision, the precision of every wire timestamp.
pub(crate) fn now_ms() -> DateTime<Utc> {
    let now = Utc::now();
    DateTime::from_timestamp_millis(now.timestamp_millis()).unwrap_or(now)
}

pub(crate) fn random32() -> [u8; 32] {
    let mut out = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut out);
    out
}

/// What a session-bound request presents.
pub(crate) struct SessionProof<'a> {
    pub(crate) route: &'static str,
    pub(crate) per_session: u32,
    pub(crate) session_id: &'a Uuid,
    pub(crate) nonce: &'a [u8; 32],
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) mac: &'a [u8; 32],
    pub(crate) context: &'a [u8],
}

/// The gate every session route passes: per-IP limit, freshness, session
/// lookup, liveness, certificate continuity, the request MAC, and only then
/// the per-session limit, so a caller without the session key cannot spend
/// the session's budget.
pub(crate) async fn authorize_session(
    state: &AppState,
    peer: &Peer,
    proof: SessionProof<'_>,
) -> Result<SessionRecord, ApiError> {
    let limits = state.inner.rate_limits;
    limit(state, &ip_key("session", peer.ip), limits.session_per_ip).await?;
    let now = Utc::now();
    check_request_freshness(proof.issued_at, now).map_err(|_| {
        ApiError::new(
            ErrorCode::StaleRequest,
            "request timestamp outside the acceptance window",
        )
    })?;
    let (record, _) = state
        .inner
        .store
        .get(proof.session_id)
        .await
        .map_err(ApiError::backend)?
        .ok_or_else(ApiError::unknown_session)?;
    ensure_live(state, &record, now).await?;
    if let Some(bound) = record.cert_sha256 {
        let same = peer
            .cert_sha256()
            .is_some_and(|presented| bool::from(presented.ct_eq(&bound)));
        if !same {
            return Err(ApiError::new(ErrorCode::InvalidMac, "request MAC rejected"));
        }
    }
    verify_request_mac(
        &record.session_key[..],
        &RequestBinding {
            session_id: proof.session_id,
            nonce: proof.nonce,
            issued_at: proof.issued_at,
            context: proof.context,
        },
        proof.mac,
    )
    .map_err(|_| ApiError::new(ErrorCode::InvalidMac, "request MAC rejected"))?;
    limit(
        state,
        &format!("{}:session:{}", proof.route, proof.session_id),
        proof.per_session,
    )
    .await?;
    Ok(record)
}

/// Dead sessions answer with their reason; a lapsed lease kills the session.
pub(crate) async fn ensure_live(
    state: &AppState,
    record: &SessionRecord,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    if let Some(reason) = record.dead {
        return Err(ApiError::dead(reason));
    }
    if record.lease.is_expired(now) {
        state
            .kill(&record.session_id, DeadReason::Expired)
            .await
            .map_err(ApiError::from_server)?;
        return Err(ApiError::dead(DeadReason::Expired));
    }
    Ok(())
}

/// Spend a request nonce; a second use inside its window is 409 `replay`.
pub(crate) async fn consume_nonce(
    state: &AppState,
    session_id: &Uuid,
    nonce: &[u8; 32],
    issued_at: DateTime<Utc>,
) -> Result<(), ApiError> {
    let fresh = state
        .inner
        .store
        .consume_nonce(session_id, *nonce, request_nonce_expiry(issued_at))
        .await
        .map_err(ApiError::backend)?;
    if fresh {
        Ok(())
    } else {
        Err(ApiError::new(ErrorCode::Replay, "nonce already used"))
    }
}

/// Re-resolve the session's grant. A lapsed grant kills the session as
/// expired; a grant pulled before its recorded expiry kills it as revoked.
pub(crate) async fn live_grant(
    state: &AppState,
    record: &SessionRecord,
) -> Result<Entitlement, ApiError> {
    let now = Utc::now();
    let grant = state
        .inner
        .entitlements
        .entitlement(&record.account, &record.product)
        .await
        .map_err(ApiError::backend)?;
    let (reason, error) = match grant {
        Some(grant) if now < grant.expires_at => return Ok(grant),
        Some(_) => (DeadReason::Expired, ApiError::dead(DeadReason::Expired)),
        None if now >= record.grant_expires_at => {
            (DeadReason::Expired, ApiError::dead(DeadReason::Expired))
        }
        None => (
            DeadReason::Revoked,
            ApiError::new(ErrorCode::NoEntitlement, "entitlement withdrawn"),
        ),
    };
    state
        .kill(&record.session_id, reason)
        .await
        .map_err(ApiError::from_server)?;
    Err(error)
}

/// Read-modify-write a session with compare-and-swap; `update` runs on a
/// fresh copy each attempt and aborts the write by returning `Err`.
pub(crate) async fn update_session<T>(
    state: &AppState,
    id: &Uuid,
    mut update: impl FnMut(&mut SessionRecord) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let store = &state.inner.store;
    for _ in 0..CAS_ATTEMPTS {
        let (mut record, version) = store
            .get(id)
            .await
            .map_err(ApiError::backend)?
            .ok_or_else(ApiError::unknown_session)?;
        if let Some(reason) = record.dead {
            return Err(ApiError::dead(reason));
        }
        let out = update(&mut record)?;
        if store
            .replace(id, version, record)
            .await
            .map_err(ApiError::backend)?
        {
            return Ok(out);
        }
        tokio::task::yield_now().await;
    }
    Err(ApiError::backend("session update kept conflicting"))
}

/// The grant's features, each valid until the grant expires.
pub(crate) fn features(grant: &Entitlement) -> Vec<FeatureGrant> {
    grant
        .features
        .iter()
        .map(|feature| FeatureGrant {
            feature: feature.clone(),
            expires_at: grant.expires_at,
        })
        .collect()
}

/// The scope and body of an envelope about to be signed.
pub(crate) struct Grant<'a, B> {
    pub(crate) challenge: [u8; 32],
    pub(crate) session_id: Uuid,
    pub(crate) audience: &'a str,
    pub(crate) operation: &'a str,
    pub(crate) issued_at: DateTime<Utc>,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) body: &'a B,
}

/// Serialize the body and sign the envelope under the active key.
pub(crate) fn sign<B: Serialize>(
    state: &AppState,
    grant: Grant<'_, B>,
) -> Result<Json<Envelope>, ApiError> {
    let body = serde_json::to_vec(grant.body).map_err(ApiError::internal)?;
    Ok(Json(Envelope::issue(
        &state.inner.issuer,
        IssueSpec {
            challenge: grant.challenge,
            session_id: grant.session_id,
            audience: grant.audience.to_string(),
            operation: grant.operation.to_string(),
            issued_at: grant.issued_at,
            expires_at: grant.expires_at,
            body,
        },
    )))
}
