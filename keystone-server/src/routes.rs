//! HTTP endpoints — the server's authority surface.
//!
//! Every route is POST + JSON. Responses that grant anything are signed
//! Envelopes; denials are `{error}` JSON with a status that tells the
//! client whether to retry (transient) or stop (dead).

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Json, Response},
    routing::{get, post},
    Extension, Router,
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use keystone_core::{
    artifact_context, artifact_key_for, decrypt_artifact, payload_wrap_key,
    verify_heartbeat_mac, verify_response_mac, wrap_artifact_key, Challenge, ConsumedSet,
    DeadReason, Entitlement, Envelope, FeatureGrant, IssueSpec, KeystoneError, KeyWrap, Lease,
    Manifest, SessionState, SignedManifest, MAX_ARTIFACT_BYTES,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::downloads::PayloadRoute;
use crate::state::{AppState, RateLimiter};
use crate::store::SessionRecord;
use crate::tls::{cert_hash_matches, peer_cert_sha256, subject_common_name, PeerCertificates};

/// Envelope audiences — a grant minted for the client must not verify
/// as a grant to the application, and vice versa.
const AUDIENCE_CLIENT: &str = "keystone-client";
const AUDIENCE_APP: &str = "keystone-app";

/// Uniform error body: `{"error": msg, "code": "..."}` plus a status
/// the client can act on. The code defaults to the status's canonical
/// reason in snake_case; `api_error_code` overrides it where the wire
/// contract names a specific code.
type ApiError = (StatusCode, Json<Value>);

fn api_error(status: StatusCode, msg: impl Into<String>) -> ApiError {
    let code = status
        .canonical_reason()
        .map(|r| r.to_ascii_lowercase().replace(' ', "_"))
        .unwrap_or_else(|| "error".to_string());
    (status, Json(json!({ "error": msg.into(), "code": code })))
}

/// Error body with a machine-readable `code` alongside the message —
/// for the codes the wire contract names explicitly.
fn api_error_code(status: StatusCode, code: &'static str, msg: impl Into<String>) -> ApiError {
    (status, Json(json!({ "error": msg.into(), "code": code })))
}

/// Stable error codes the client parses out of `{"error", "code"}`.
/// `bad_challenge` and `rate_limited` are transient — retryable, never
/// a verdict on the session. The artifact codes mark payload failures
/// that must not kill a session either.
const CODE_BAD_CHALLENGE: &str = "bad_challenge";
const CODE_RATE_LIMITED: &str = "rate_limited";
const CODE_ARTIFACT_NOT_FOUND: &str = "artifact_not_found";
const CODE_SESSION_NOT_ACTIVE: &str = "session_not_active";
const CODE_ARTIFACT_INVALID: &str = "artifact_invalid";

/// KeystoneError → HTTP status. The distinctions matter: 401 says
/// "prove yourself again", 403 says "denied", 410 says "this grant is
/// over", 409 says "already seen".
fn keystone_status(e: &KeystoneError) -> StatusCode {
    match e {
        KeystoneError::InvalidSignature
        | KeystoneError::InvalidMac
        | KeystoneError::ChallengeMismatch => StatusCode::UNAUTHORIZED,
        KeystoneError::AlreadyConsumed => StatusCode::CONFLICT,
        KeystoneError::Expired | KeystoneError::GraceExhausted => StatusCode::GONE,
        KeystoneError::Revoked
        | KeystoneError::NoEntitlement(_)
        | KeystoneError::SessionMismatch => StatusCode::FORBIDDEN,
        KeystoneError::AudienceMismatch { .. }
        | KeystoneError::OperationMismatch { .. }
        | KeystoneError::Malformed(_)
        | KeystoneError::ClockSkew => StatusCode::BAD_REQUEST,
    }
}

fn dead_session_error(reason: DeadReason) -> ApiError {
    match reason {
        DeadReason::Rejected | DeadReason::Revoked => {
            api_error(StatusCode::FORBIDDEN, KeystoneError::Revoked.to_string())
        }
        DeadReason::Expired => {
            api_error(StatusCode::GONE, KeystoneError::Expired.to_string())
        }
        DeadReason::GraceExhausted => {
            api_error(StatusCode::GONE, KeystoneError::GraceExhausted.to_string())
        }
    }
}

/// KeystoneError → ApiError with status and code both derived from the
/// error — the single mapping point for core rejections.
fn keystone_error(e: KeystoneError) -> ApiError {
    api_error(keystone_status(&e), e.to_string())
}

/// Sliding-window check: over the limit is 429 + `rate_limited` —
/// transient, never a verdict on the session.
fn rate_limit(state: &AppState, key: &str, limit: u32) -> Result<(), ApiError> {
    if state.rate_limiter.check(key, limit) {
        Ok(())
    } else {
        Err(api_error_code(
            StatusCode::TOO_MANY_REQUESTS,
            CODE_RATE_LIMITED,
            "rate limited",
        ))
    }
}

/// Re-resolve the session's grant against the live entitlement
/// backend. This is what makes revocation real: a grant pulled (or
/// lapsed) since the exchange kills the session on its next
/// heartbeat/attest instead of riding out the recorded expiry, and a
/// grant extended since then flows back into the record.
///
/// `recorded_expiry` distinguishes the two `None` cases the backend
/// can't: if the grant we knew about already lapsed, the session dies
/// Expired; if it was still live on our books but the backend no
/// longer returns it, it was pulled — Revoked.
async fn resolve_live_grant(
    state: &AppState,
    session_id: &Uuid,
    account: &str,
    product: &str,
    recorded_expiry: DateTime<Utc>,
) -> Result<Entitlement, ApiError> {
    let now = Utc::now();
    match state
        .entitlements
        .entitlement(account, product)
        .await
        .map_err(|e| backend_error(&e))?
    {
        Some(grant) if now < grant.expires_at => Ok(grant),
        Some(_) => {
            state.store.with_mut(session_id, |rec| {
                rec.state.kill(DeadReason::Expired);
            });
            Err(api_error(
                StatusCode::GONE,
                KeystoneError::Expired.to_string(),
            ))
        }
        None => {
            let (reason, err) = if now >= recorded_expiry {
                (DeadReason::Expired, KeystoneError::Expired.to_string())
            } else {
                (DeadReason::Revoked, KeystoneError::Revoked.to_string())
            };
            state.store.with_mut(session_id, |rec| {
                rec.state.kill(reason);
            });
            let status = match reason {
                DeadReason::Expired => StatusCode::GONE,
                _ => StatusCode::FORBIDDEN,
            };
            Err(api_error(status, err))
        }
    }
}

/// A session_id is a bearer-shaped identifier — never write it to logs
/// where it could be lifted and replayed. Log a truncated sha256
/// prefix instead: enough to correlate, useless to replay.
fn sid_tag(session_id: &Uuid) -> String {
    hex::encode(&Sha256::digest(session_id.as_bytes())[..8])
}

/// Backend failures get logged with detail server-side; the client
/// sees a static string — internals are not the caller's business.
fn backend_error(e: &KeystoneError) -> ApiError {
    tracing::error!(error = %e, "entitlement backend failure");
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "entitlement backend unavailable",
    )
}

/// Consume a server-issued challenge. Unknown, expired, and reused
/// nonces are indistinguishable — all are 401 `bad_challenge`: a
/// transient failure the client retries with a fresh challenge, never
/// a verdict on a session.
fn consume_challenge(state: &AppState, nonce: &[u8; 32]) -> Result<(), ApiError> {
    state.challenges.consume(nonce, Utc::now()).map_err(|_| {
        api_error_code(StatusCode::UNAUTHORIZED, CODE_BAD_CHALLENGE, "invalid challenge")
    })
}

/// Reclaim dead weight on every request — cheap, and it keeps the
/// store and challenge book bounded without a background task.
async fn sweep_middleware(State(state): State<AppState>, req: axum::extract::Request, next: Next) -> Response {
    let now = Utc::now();
    state.store.sweep(now);
    state.challenges.evict_expired(now);
    next.run(req).await
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/challenge", post(challenge))
        .route("/exchange", post(exchange))
        .route("/attest", post(attest))
        .route("/heartbeat", post(heartbeat))
        .route("/revoke", post(revoke))
        .route("/payload", post(payload_fetch))
        .route("/payload/:product/:version", get(payload_blob))
        .layer(middleware::from_fn_with_state(state.clone(), sweep_middleware))
        .with_state(state)
}

/// Mint a fresh challenge. The client echoes the nonce into /exchange;
/// the server records it so only server-issued, unexpired, unspent
/// nonces are ever accepted.
async fn challenge(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<Value>, ApiError> {
    rate_limit(
        &state,
        &RateLimiter::ip_key("challenge", peer.map(|ConnectInfo(a)| a.ip())),
        state.rate_limits.challenge_per_ip,
    )?;
    let c = Challenge::fresh(state.challenge_ttl);
    state.challenges.issue(c.nonce, c.issued_at + c.ttl);
    Ok(Json(json!({
        "nonce": c.nonce,
        "issued_at": c.issued_at,
        "ttl_secs": c.ttl.num_seconds(),
    })))
}

#[derive(Deserialize)]
struct ExchangeRequest {
    account: String,
    secret: String,
    product: String,
    /// Client-supplied HWID fingerprint — hashed before storage; an
    /// anomaly signal, not a hard gate (DESIGN.md: assume spoofable).
    #[serde(with = "serde_big_array::BigArray")]
    hwid: [u8; 32],
    #[serde(with = "serde_big_array::BigArray")]
    challenge: [u8; 32],
}

/// The exchange body is the only place the session key ever appears —
/// inside a signed envelope to the client. It is never logged, never
/// stored anywhere but the session record.
#[derive(Serialize)]
struct ExchangeBody {
    session_id: Uuid,
    #[serde(with = "serde_big_array::BigArray")]
    session_key: [u8; 32],
    lease: Lease,
    /// Server clock at issue — the client validates drift against it
    /// (RSW lesson: a static response has no time anchor).
    server_time: DateTime<Utc>,
}

async fn exchange(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    peer_certs: Option<Extension<PeerCertificates>>,
    Json(req): Json<ExchangeRequest>,
) -> Result<Json<Envelope>, ApiError> {
    let now = Utc::now();

    // Rate limits before any real work: the per-IP bucket bounds the
    // argon2 cost a flood can inflict, the per-account bucket catches
    // credential stuffing from rotating IPs.
    rate_limit(
        &state,
        &RateLimiter::ip_key("exchange", peer.map(|ConnectInfo(a)| a.ip())),
        state.rate_limits.exchange_per_ip,
    )?;
    rate_limit(
        &state,
        &format!("exchange:account:{}", req.account),
        state.rate_limits.exchange_per_account,
    )?;

    // The challenge is spent even if auth fails — a burned nonce is
    // cheaper than a reusable one.
    consume_challenge(&state, &req.challenge)?;

    // Authentication first — always. Running cert checks before the
    // argon2 verify would let an attacker probe account/cert bindings
    // without valid credentials, and answering cert failures
    // differently would reveal the secret was right. Every failure
    // from here to the entitlement check is the same 401.
    state
        .entitlements
        .authenticate(&req.account, &req.secret)
        .await
        .map_err(|e| backend_error(&e))?
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "invalid credentials"))?;

    // Certificate binding: when the account pins a client cert, the
    // TLS peer must present exactly it AND its CN must name the
    // account. Mismatches are indistinguishable from bad credentials —
    // the response must never confirm the secret was valid.
    if let Some(pinned) = state
        .entitlements
        .cert_sha256(&req.account)
        .await
        .map_err(|e| backend_error(&e))?
    {
        let presented = peer_certs
            .as_ref()
            .and_then(|Extension(peers)| peer_cert_sha256(peers));
        let Some(presented) = presented else {
            return Err(api_error(StatusCode::UNAUTHORIZED, "invalid credentials"));
        };
        if !cert_hash_matches(&presented, &pinned) {
            return Err(api_error(StatusCode::UNAUTHORIZED, "invalid credentials"));
        }
        let cn = peer_certs
            .as_ref()
            .and_then(|Extension(peers)| peers.0.first())
            .and_then(|leaf| {
                webpki::EndEntityCert::try_from(leaf)
                    .ok()
                    .and_then(|cert| subject_common_name(cert.subject()))
            });
        if cn.as_deref() != Some(req.account.as_str()) {
            return Err(api_error(StatusCode::UNAUTHORIZED, "invalid credentials"));
        }
    }

    // Authorization: what are they allowed. A valid login with no
    // grant for the requested product still fails — as 403, not 401:
    // they proved who they are, they're just not allowed this.
    let grant = state
        .entitlements
        .entitlement(&req.account, &req.product)
        .await
        .map_err(|e| backend_error(&e))?
        .ok_or_else(|| {
            api_error(
                StatusCode::FORBIDDEN,
                KeystoneError::NoEntitlement(req.product.clone()).to_string(),
            )
        })?;
    if now >= grant.expires_at {
        return Err(api_error(StatusCode::GONE, KeystoneError::Expired.to_string()));
    }

    let session_id = Uuid::new_v4();
    let mut session_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_key);
    // The lease never outlives the grant behind it.
    let lease_expiry = std::cmp::min(now + state.lease_ttl, grant.expires_at);
    let lease = Lease {
        session_id,
        granted_at: now,
        expires_at: lease_expiry,
        grace_period: state.grace_period,
    };
    let hwid_hash: [u8; 32] = Sha256::digest(req.hwid).into();
    // Anomaly signal, not a gate: same account, different fingerprint,
    // short window → flag it. Never blocks — HWID is spoofable by
    // design (facade exists); this feeds investigation, not denial.
    if state.store.check_fingerprint(
        &req.account,
        hwid_hash,
        now,
        chrono::Duration::minutes(10),
    ) {
        tracing::warn!(account = %req.account, "hwid anomaly: new fingerprint within window");
    }
    state.store.insert(SessionRecord {
        session_id,
        account: req.account,
        product: req.product,
        hwid_hash,
        session_key,
        entitlement_expires_at: grant.expires_at,
        state: SessionState::Active {
            lease: lease.clone(),
        },
        consumed: ConsumedSet::new(),
        created_at: now,
    });
    tracing::debug!(session = %sid_tag(&session_id), "session created");

    let body = serde_json::to_vec(&ExchangeBody {
        session_id,
        session_key,
        lease,
        server_time: now,
    })
    .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(Envelope::issue(
        &state.issuer,
        IssueSpec {
            challenge: req.challenge,
            session_id,
            audience: AUDIENCE_CLIENT.into(),
            operation: "session.exchange".into(),
            issued_at: now,
            // The signature never attests a window the lease doesn't
            // grant.
            expires_at: lease_expiry,
            body,
        },
    )))
}

#[derive(Deserialize)]
struct AttestRequest {
    session_id: Uuid,
    #[serde(with = "serde_big_array::BigArray")]
    challenge: [u8; 32],
    /// The application's self-reported identity. Logged as an anomaly
    /// signal — never trusted as proof on its own.
    process_id: String,
    /// Proof of session-key possession — without it, a bare session_id
    /// would be a bearer token anyone holding it could attest with.
    /// Optional in the wire shape so a missing MAC is a 401, not a
    /// deserialization error.
    mac: Option<[u8; 32]>,
}

#[derive(Serialize)]
struct LeaseBody {
    lease: Lease,
    server_time: DateTime<Utc>,
}

/// The application's independent attestation (DESIGN.md step 6): the
/// app never trusts "the client already checked" — it presents the
/// session itself, proves session-key possession, and gets its own
/// signed lease.
async fn attest(
    State(state): State<AppState>,
    Json(req): Json<AttestRequest>,
) -> Result<Json<Envelope>, ApiError> {
    let now = Utc::now();
    consume_challenge(&state, &req.challenge)?;

    // Phase 1, under the store lock: the session must be live and the
    // MAC must verify before the backend is touched — a valid tag on
    // a dead session must never reach the entitlement lookup.
    let (account, product, recorded_expiry) = state
        .store
        .with_mut(&req.session_id, |rec| {
            match &rec.state {
                SessionState::Active { lease } if !lease.is_expired(now) => {}
                SessionState::Active { .. } => {
                    return Err(api_error(StatusCode::GONE, KeystoneError::Expired.to_string()))
                }
                SessionState::Dead { reason } => return Err(dead_session_error(*reason)),
                // The server is authoritative: it only ever creates
                // Active or Dead — Grace is client-side bookkeeping.
                // A Grace record here means the store was seeded from
                // outside; deny it rather than attest borrowed time.
                SessionState::Grace { .. } => {
                    return Err(api_error_code(
                        StatusCode::FORBIDDEN,
                        CODE_SESSION_NOT_ACTIVE,
                        "session not active",
                    ))
                }
            }
            let mac = req.mac.ok_or_else(|| {
                api_error(StatusCode::UNAUTHORIZED, KeystoneError::InvalidMac.to_string())
            })?;
            verify_response_mac(&rec.session_key, &req.challenge, b"attest", &mac)
                .map_err(keystone_error)?;
            rec.consumed.evict_expired(now);
            Ok((
                rec.account.clone(),
                rec.product.clone(),
                rec.entitlement_expires_at,
            ))
        })
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "unknown session"))??;

    // Phase 2, outside the lock: the grant is re-resolved live — a
    // pull or lapse kills the session now, an extension flows back in.
    let grant = resolve_live_grant(
        &state,
        &req.session_id,
        &account,
        &product,
        recorded_expiry,
    )
    .await?;

    // Phase 3, back under the lock: the session may have been revoked
    // while the backend call was in flight — re-check before issuing.
    let lease = state
        .store
        .with_mut(&req.session_id, |rec| {
            let now = Utc::now();
            rec.entitlement_expires_at = grant.expires_at;
            match &rec.state {
                SessionState::Active { lease } if !lease.is_expired(now) => Ok(lease.clone()),
                SessionState::Active { .. } => {
                    Err(api_error(StatusCode::GONE, KeystoneError::Expired.to_string()))
                }
                SessionState::Dead { reason } => Err(dead_session_error(*reason)),
                SessionState::Grace { .. } => Err(api_error_code(
                    StatusCode::FORBIDDEN,
                    CODE_SESSION_NOT_ACTIVE,
                    "session not active",
                )),
            }
        })
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "unknown session"))??;

    tracing::debug!(session = %sid_tag(&req.session_id), process_id = %req.process_id, "attest");
    let body = serde_json::to_vec(&LeaseBody {
        lease: lease.clone(),
        server_time: now,
    })
    .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(Envelope::issue(
        &state.issuer,
        IssueSpec {
            challenge: req.challenge,
            session_id: req.session_id,
            audience: AUDIENCE_APP.into(),
            operation: "session.attest".into(),
            issued_at: now,
            // The signature never attests a window the lease or the
            // live grant doesn't cover — a grant shortened since the
            // lease was issued caps the attestation.
            expires_at: std::cmp::min(lease.expires_at, grant.expires_at),
            body,
        },
    )))
}

#[derive(Deserialize)]
struct HeartbeatRequest {
    session_id: Uuid,
    #[serde(with = "serde_big_array::BigArray")]
    nonce: [u8; 32],
    /// HMAC over DOMAIN_HEARTBEAT + session_id + nonce, keyed by the
    /// session key — proves the caller holds the material issued at
    /// exchange. A captured heartbeat can't be replayed into another
    /// session.
    #[serde(with = "serde_big_array::BigArray")]
    mac: [u8; 32],
}

/// Signed keepalive: renews the lease. A heartbeat is not a
/// connectivity check — a reachable server still rejects dead
/// sessions, expired grants, bad MACs, and replays.
async fn heartbeat(
    State(state): State<AppState>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<Envelope>, ApiError> {
    let now = Utc::now();
    let lease_ttl = state.lease_ttl;
    let grace_period = state.grace_period;

    // Phase 1, under the store lock: dead stays dead and the MAC must
    // verify before the backend is touched — a valid tag on a dead
    // session must never reach the entitlement lookup. The recorded
    // entitlement expiry is NOT checked here: it may be stale (a grant
    // extension must be able to rescue the session), so expiry is
    // decided by the live re-resolution below.
    let (account, product, recorded_expiry) = state
        .store
        .with_mut(&req.session_id, |rec| {
            match &rec.state {
                SessionState::Dead { reason } => return Err(dead_session_error(*reason)),
                // An Active session whose lease already expired is
                // over — kill it rather than renew a lapsed grant.
                SessionState::Active { lease } if lease.is_expired(now) => {
                    rec.state.kill(DeadReason::Expired);
                    return Err(api_error(StatusCode::GONE, KeystoneError::Expired.to_string()));
                }
                SessionState::Active { .. } => {}
                // The server is authoritative: it only ever creates
                // Active or Dead — Grace is client-side bookkeeping.
                // A Grace record here means the store was seeded from
                // outside; deny it rather than renew borrowed time.
                SessionState::Grace { .. } => {
                    return Err(api_error_code(
                        StatusCode::FORBIDDEN,
                        CODE_SESSION_NOT_ACTIVE,
                        "session not active",
                    ))
                }
            }
            verify_heartbeat_mac(&rec.session_key, &rec.session_id, &req.nonce, &req.mac)
                .map_err(keystone_error)?;
            Ok((
                rec.account.clone(),
                rec.product.clone(),
                rec.entitlement_expires_at,
            ))
        })
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "unknown session"))??;

    // Phase 2, outside the lock: the grant is re-resolved live — a
    // pull or lapse kills the session now, an extension flows back in.
    let grant = resolve_live_grant(
        &state,
        &req.session_id,
        &account,
        &product,
        recorded_expiry,
    )
    .await?;

    // Phase 3, back under the lock: the session may have been revoked
    // while the backend call was in flight — re-check before renewing.
    // The nonce is consumed here, after the grant check, so a backend
    // outage doesn't burn it; the check-and-mark stays atomic under
    // the lock, so exactly one of N concurrent heartbeats wins a nonce.
    let lease = state
        .store
        .with_mut(&req.session_id, |rec| {
            let now = Utc::now();
            rec.entitlement_expires_at = grant.expires_at;
            match &rec.state {
                SessionState::Dead { reason } => return Err(dead_session_error(*reason)),
                SessionState::Active { lease } if lease.is_expired(now) => {
                    rec.state.kill(DeadReason::Expired);
                    return Err(api_error(StatusCode::GONE, KeystoneError::Expired.to_string()));
                }
                SessionState::Active { .. } => {}
                SessionState::Grace { .. } => {
                    return Err(api_error_code(
                        StatusCode::FORBIDDEN,
                        CODE_SESSION_NOT_ACTIVE,
                        "session not active",
                    ))
                }
            }
            rec.consumed.evict_expired(now);
            let lease = Lease {
                session_id: rec.session_id,
                granted_at: now,
                // Renewal is capped by the grant — the lease never
                // outlives the entitlement.
                expires_at: std::cmp::min(now + lease_ttl, grant.expires_at),
                grace_period,
            };
            // Nonces are remembered for the session's whole life, not
            // the rolling lease — a captured heartbeat must stay dead
            // after a renewal moves the lease window forward.
            rec.consumed
                .consume(req.nonce, grant.expires_at)
                .map_err(keystone_error)?;
            rec.state.on_heartbeat_ok(lease.clone());
            Ok(lease)
        })
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "unknown session"))??;

    let body = serde_json::to_vec(&LeaseBody {
        lease: lease.clone(),
        server_time: now,
    })
    .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(Envelope::issue(
        &state.issuer,
        IssueSpec {
            challenge: req.nonce,
            session_id: req.session_id,
            audience: AUDIENCE_CLIENT.into(),
            operation: "session.heartbeat".into(),
            issued_at: now,
            expires_at: lease.expires_at,
            body,
        },
    )))
}

#[derive(Deserialize)]
struct RevokeRequest {
    /// Kill one session. Exactly one of session_id/account is required.
    session_id: Option<Uuid>,
    /// Kill every live session belonging to this account.
    account: Option<String>,
    /// Operator credential from KEYSTONE_ADMIN_TOKEN. Optional in the
    /// wire shape so a missing token is a 403, not a parse error.
    admin_token: Option<String>,
}

/// Explicit revocation — immediate death, no grace.
///
/// Gated on KEYSTONE_ADMIN_TOKEN: without it configured the route is
/// closed entirely. The comparison is constant-time over sha256 hashes
/// so neither length nor content leaks through timing.
async fn revoke(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    rate_limit(
        &state,
        &RateLimiter::ip_key("revoke", peer.map(|ConnectInfo(a)| a.ip())),
        state.rate_limits.revoke_per_ip,
    )?;
    let authorized = match (&state.admin_token_hash, &req.admin_token) {
        (Some(expected), Some(token)) => {
            let presented: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            presented.ct_eq(expected).into()
        }
        _ => false,
    };
    if !authorized {
        return Err(api_error(StatusCode::FORBIDDEN, "forbidden"));
    }
    match (req.session_id, req.account) {
        (Some(session_id), None) => {
            if state.store.revoke(&session_id) {
                tracing::info!(session = %sid_tag(&session_id), "session revoked");
                Ok(Json(json!({ "revoked": true })))
            } else {
                Err(api_error(StatusCode::NOT_FOUND, "unknown session"))
            }
        }
        (None, Some(account)) => {
            let killed = state.store.revoke_account(&account);
            tracing::info!(account = %account, killed, "account sessions revoked");
            Ok(Json(json!({ "revoked": killed })))
        }
        _ => Err(api_error(
            StatusCode::BAD_REQUEST,
            "exactly one of session_id or account is required",
        )),
    }
}

#[derive(Deserialize)]
struct PayloadRequest {
    session_id: Uuid,
    product: String,
    version: String,
    /// Client-generated nonce — echoed into the signed envelope and
    /// used as the HKDF salt for the key wrap, so a captured wrap
    /// can't be unwrapped outside this request.
    #[serde(with = "serde_big_array::BigArray")]
    nonce: [u8; 32],
    /// Proof of session-key possession — without it a bare session_id
    /// would be a bearer token anyone holding it could fetch with.
    /// Optional in the wire shape so a missing MAC is a 401, not a
    /// deserialization error.
    mac: Option<[u8; 32]>,
}

/// The signed body of a payload.fetch envelope: the manifest the
/// payload verifies against, and the artifact key wrapped under
/// session-derived material — it exists only because a live exchange
/// happened, which is what makes download ≠ runtime.
#[derive(Serialize)]
struct PayloadBody {
    manifest: SignedManifest,
    payload_key_wrap: KeyWrap,
}

/// What a payload request proved about its session. The wrap key is
/// derived inside the store lock so the session key never gets copied
/// out of the record.
struct PayloadGate {
    account: String,
    lease_expires_at: DateTime<Utc>,
    wrap_key: [u8; 32],
}

/// Shared gate for both payload routes: live session, valid MAC, nonce
/// consumed. Mirrors attest's ordering — dead sessions are rejected
/// before the MAC so a valid tag can never resurrect a revoked session.
fn gate_payload_request(
    state: &AppState,
    session_id: &Uuid,
    nonce: &[u8; 32],
    mac: Option<&[u8; 32]>,
    mac_body: &[u8],
) -> Result<PayloadGate, ApiError> {
    let now = Utc::now();
    state
        .store
        .with_mut(session_id, |rec| {
            let lease_expires_at = match &rec.state {
                SessionState::Active { lease } if !lease.is_expired(now) => lease.expires_at,
                // An Active session whose lease already expired is
                // over — kill it rather than serve a lapsed grant.
                SessionState::Active { .. } => {
                    rec.state.kill(DeadReason::Expired);
                    return Err(api_error(StatusCode::GONE, KeystoneError::Expired.to_string()))
                }
                SessionState::Dead { reason } => return Err(dead_session_error(*reason)),
                // The server is authoritative: it only ever creates
                // Active or Dead — Grace is client-side bookkeeping.
                // A Grace record here means the store was seeded from
                // outside; deny it rather than serve borrowed time.
                SessionState::Grace { .. } => {
                    return Err(api_error_code(
                        StatusCode::FORBIDDEN,
                        CODE_SESSION_NOT_ACTIVE,
                        "session not active",
                    ))
                }
            };
            let mac = mac.ok_or_else(|| {
                api_error(StatusCode::UNAUTHORIZED, KeystoneError::InvalidMac.to_string())
            })?;
            verify_response_mac(&rec.session_key, nonce, mac_body, mac)
                .map_err(keystone_error)?;
            rec.consumed.evict_expired(now);
            // Nonces are remembered for the session's whole life, not
            // the rolling lease — a captured MAC must stay dead after
            // a renewal moves the lease window forward.
            rec.consumed
                .consume(*nonce, rec.entitlement_expires_at)
                .map_err(keystone_error)?;
            Ok(PayloadGate {
                account: rec.account.clone(),
                lease_expires_at,
                wrap_key: payload_wrap_key(&rec.session_key, nonce),
            })
        })
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "unknown session"))?
}

/// Path segments become filenames — reject anything that could escape
/// the payload directory or smuggle a separator through.
fn valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !s.starts_with('.')
        && !s.contains("..")
}

/// Resolve `{product}-{version}.bin` inside the configured directory
/// plus the artifact secret. Both halves configured or the routes are
/// closed — a dir without the secret can serve only ciphertext nobody
/// can open, so 503 covers either missing piece.
fn payload_store(
    state: &AppState,
    product: &str,
    version: &str,
) -> Result<(PathBuf, [u8; 32]), ApiError> {
    let (dir, secret) = match (&state.payload_dir, &state.payload_secret) {
        (Some(dir), Some(secret)) => (dir, *secret),
        _ => {
            return Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "payload store not configured",
            ))
        }
    };
    if !valid_segment(product) || !valid_segment(version) {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid product or version"));
    }
    Ok((dir.join(format!("{product}-{version}.bin")), secret))
}

/// The build identifier stamped into the manifest and download
/// records. `xtask seal` writes it to a `{product}-{version}.build`
/// sidecar next to the blob; artifacts sealed before sidecars existed
/// fall back to a content-derived id so they stay attributable.
async fn build_id_for(path: &std::path::Path, sealed: &[u8]) -> String {
    let sidecar = path.with_extension("build");
    match tokio::fs::read_to_string(&sidecar).await {
        Ok(id) if !id.trim().is_empty() => id.trim().to_string(),
        _ => format!("sha256:{}", hex::encode(&Sha256::digest(sealed)[..8])),
    }
}

/// Read a sealed artifact with a hard size cap. A missing file is
/// `artifact_not_found` — transient, never a verdict on the session.
/// Anything shorter than nonce+tag is plaintext or garbage and is
/// refused rather than served.
async fn read_artifact(path: &PathBuf) -> Result<Vec<u8>, ApiError> {
    let meta = tokio::fs::metadata(path).await.map_err(|_| {
        api_error_code(StatusCode::NOT_FOUND, CODE_ARTIFACT_NOT_FOUND, "no such payload")
    })?;
    if meta.len() > MAX_ARTIFACT_BYTES {
        return Err(api_error_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            CODE_ARTIFACT_INVALID,
            "artifact too large",
        ));
    }
    let sealed = tokio::fs::read(path).await.map_err(|_| {
        api_error_code(StatusCode::NOT_FOUND, CODE_ARTIFACT_NOT_FOUND, "no such payload")
    })?;
    if sealed.len() < 24 + 16 {
        return Err(api_error_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            CODE_ARTIFACT_INVALID,
            "artifact not sealed",
        ));
    }
    Ok(sealed)
}

/// The plaintext sha256 the manifest attests — what runs, not what
/// sits on disk. `xtask seal` writes it to a `{product}-{version}
/// .sha256` sidecar so the server never decrypts per manifest request;
/// without a sidecar the blob is decrypted and hashed once, then
/// cached by (path, mtime) so a re-sealed artifact can't serve a
/// stale hash. A blob that fails to unseal is a corrupt artifact, not
/// a client problem: 422, session untouched.
async fn artifact_plaintext_sha256(
    state: &AppState,
    path: &PathBuf,
    artifact_key: &[u8; 32],
    sealed: &[u8],
) -> Result<[u8; 32], ApiError> {
    let invalid = |msg: &'static str| {
        api_error_code(StatusCode::UNPROCESSABLE_ENTITY, CODE_ARTIFACT_INVALID, msg)
    };
    let sidecar = path.with_extension("sha256");
    if let Ok(text) = tokio::fs::read_to_string(&sidecar).await {
        let bytes = hex::decode(text.trim()).map_err(|_| invalid("bad .sha256 sidecar"))?;
        return bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid("bad .sha256 sidecar"));
    }
    let mtime = tokio::fs::metadata(path)
        .await
        .and_then(|m| m.modified())
        .ok();
    if let Some(mtime) = mtime
        && let Some(hash) = state.artifact_hashes.get(path, mtime)
    {
        return Ok(hash);
    }
    let plaintext = decrypt_artifact(artifact_key, sealed)
        .map_err(|_| invalid("artifact failed to unseal"))?;
    let hash: [u8; 32] = Sha256::digest(&plaintext).into();
    if let Some(mtime) = mtime {
        state.artifact_hashes.insert(path.clone(), mtime, hash);
    }
    Ok(hash)
}

/// The per-request manifest watermark: hex(HMAC-SHA256(watermark
/// secret, account‖session_id‖build_id‖issued_at_rfc3339)). A captured
/// manifest ties back to the exact download that produced it. Empty
/// when no watermark secret is configured — the manifest still
/// verifies, it just isn't attributable.
fn download_id_for(
    state: &AppState,
    account: &str,
    session_id: &Uuid,
    build_id: &str,
    issued_at: DateTime<Utc>,
) -> String {
    let Some(secret) = &state.watermark_secret else {
        return String::new();
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(account.as_bytes());
    mac.update(session_id.as_bytes());
    mac.update(build_id.as_bytes());
    mac.update(issued_at.to_rfc3339().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// POST /payload — the session-gated manifest fetch. Returns a signed
/// envelope carrying the manifest and the artifact key wrapped under
/// session-derived material; the sealed blob itself comes from
/// GET /payload/{product}/{version} so the signed envelope stays small.
async fn payload_fetch(
    State(state): State<AppState>,
    Json(req): Json<PayloadRequest>,
) -> Result<Json<Envelope>, ApiError> {
    let now = Utc::now();
    let (path, secret) = payload_store(&state, &req.product, &req.version)?;
    let context = artifact_context(&req.product, &req.version);
    // The MAC binds product+version — a tag minted for one artifact
    // can't be transplanted onto another.
    let mac_body = [b"payload.fetch:".as_slice(), &context].concat();
    let gate = gate_payload_request(
        &state,
        &req.session_id,
        &req.nonce,
        req.mac.as_ref(),
        &mac_body,
    )?;

    // Authorization is re-checked per request, not inherited from the
    // exchange — a grant can lapse or be pulled while the session
    // lives, and the feature list below comes from the live record.
    let grant = state
        .entitlements
        .entitlement(&gate.account, &req.product)
        .await
        .map_err(|e| backend_error(&e))?
        .ok_or_else(|| {
            api_error(
                StatusCode::FORBIDDEN,
                KeystoneError::NoEntitlement(req.product.clone()).to_string(),
            )
        })?;
    if now >= grant.expires_at {
        return Err(api_error(StatusCode::GONE, KeystoneError::Expired.to_string()));
    }

    let sealed = read_artifact(&path).await?;
    let artifact_key = artifact_key_for(&secret, &context, &sealed).map_err(|_| {
        api_error_code(
            StatusCode::UNPROCESSABLE_ENTITY,
            CODE_ARTIFACT_INVALID,
            "artifact not sealed",
        )
    })?;
    // The manifest attests the *plaintext* hash — the client verifies
    // after decrypting, so the signature must cover what runs, not
    // what sits on disk. The `.sha256` sidecar (or the mtime-keyed
    // cache) supplies it without a per-request decrypt.
    let plaintext_sha256 =
        artifact_plaintext_sha256(&state, &path, &artifact_key, &sealed).await?;

    let build_id = build_id_for(&path, &sealed).await;

    // The manifest never attests a window the lease or the grant
    // doesn't cover — a manifest that outlived either would keep
    // authorizing after the server stopped.
    let manifest_expiry = std::cmp::min(gate.lease_expires_at, grant.expires_at);
    let signed = SignedManifest::issue(
        &state.issuer,
        Manifest {
            product: req.product.clone(),
            version: req.version.clone(),
            build_id: build_id.clone(),
            // Signed per request — a captured manifest ties back to
            // the exact download that produced it.
            download_id: download_id_for(
                &state,
                &gate.account,
                &req.session_id,
                &build_id,
                now,
            ),
            sha256: plaintext_sha256,
            feature_grants: grant
                .features
                .iter()
                .map(|feature| FeatureGrant {
                    feature: feature.clone(),
                    expires_at: grant.expires_at,
                })
                .collect(),
            issued_at: now,
            expires_at: manifest_expiry,
        },
    );


    let body = serde_json::to_vec(&PayloadBody {
        manifest: signed,
        payload_key_wrap: wrap_artifact_key(&gate.wrap_key, &artifact_key),
    })
    .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::debug!(session = %sid_tag(&req.session_id), product = %req.product, "payload manifest issued");
    if let Some(log) = &state.downloads
        && let Err(e) = log.record(
            PayloadRoute::ManifestIssued,
            &gate.account,
            &req.product,
            &req.version,
            &build_id,
            &sid_tag(&req.session_id),
        )
    {
        // Evidence, not proof — a logging failure must never fail
        // a download that already passed every gate.
        tracing::warn!("download log write failed: {e}");
    }
    Ok(Json(Envelope::issue(
        &state.issuer,
        IssueSpec {
            challenge: req.nonce,
            session_id: req.session_id,
            audience: AUDIENCE_APP.into(),
            operation: "payload.fetch".into(),
            issued_at: now,
            expires_at: manifest_expiry,
            body,
        },
    )))
}

/// Parse `Authorization: Keystone <session_id>:<nonce_hex>:<mac_hex>`.
/// The MAC is over `payload.download:` ++ artifact_context(product,
/// version) — a tag minted for one artifact can't be transplanted onto
/// another, and the nonce is consumed per session so a captured header
/// can't be replayed.
fn parse_payload_auth(headers: &HeaderMap) -> Result<(Uuid, [u8; 32], [u8; 32]), ApiError> {
    let bad = || api_error(StatusCode::UNAUTHORIZED, "invalid authorization header");
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Keystone "))
        .ok_or_else(bad)?;
    let mut parts = value.split(':');
    let session_id: Uuid = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(bad)?;
    let nonce_vec = parts.next().and_then(|s| hex::decode(s).ok()).ok_or_else(bad)?;
    let mac_vec = parts.next().and_then(|s| hex::decode(s).ok()).ok_or_else(bad)?;
    if parts.next().is_some() {
        return Err(bad());
    }
    let nonce: [u8; 32] = nonce_vec.try_into().map_err(|_| bad())?;
    let mac: [u8; 32] = mac_vec.try_into().map_err(|_| bad())?;
    Ok((session_id, nonce, mac))
}

/// GET /payload/{product}/{version} — the sealed blob download. Same
/// session gate as the manifest fetch; the MAC travels in the
/// Authorization header because GETs carry no body.
async fn payload_blob(
    State(state): State<AppState>,
    Path((product, version)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Vec<u8>, ApiError> {
    let now = Utc::now();
    let (path, _secret) = payload_store(&state, &product, &version)?;
    let (session_id, nonce, mac) = parse_payload_auth(&headers)?;
    let context = artifact_context(&product, &version);
    let mac_body = [b"payload.download:".as_slice(), &context].concat();
    let gate = gate_payload_request(
        &state,
        &session_id,
        &nonce,
        Some(&mac),
        &mac_body,
    )?;

    // The blob route re-checks the grant — a successful manifest fetch
    // is not a standing download permission.
    let grant = state
        .entitlements
        .entitlement(&gate.account, &product)
        .await
        .map_err(|e| backend_error(&e))?
        .ok_or_else(|| {
            api_error(
                StatusCode::FORBIDDEN,
                KeystoneError::NoEntitlement(product.clone()).to_string(),
            )
        })?;
    if now >= grant.expires_at {
        return Err(api_error(StatusCode::GONE, KeystoneError::Expired.to_string()));
    }

    let sealed = read_artifact(&path).await?;
    if let Some(log) = &state.downloads {
        let build_id = build_id_for(&path, &sealed).await;
        if let Err(e) = log.record(
            PayloadRoute::BlobServed,
            &gate.account,
            &product,
            &version,
            &build_id,
            &sid_tag(&session_id),
        ) {
            tracing::warn!("download log write failed: {e}");
        }
    }
    Ok(sealed)
}
