//! `POST /exchange`: credentials for a new loader session.

use axum::extract::State;
use axum::response::Json;
use keystone_core::wire::{AUDIENCE_CLIENT, ErrorCode, ExchangeBody, ExchangeRequest, OP_EXCHANGE};
use keystone_core::{DeadReason, Envelope, Lease};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::AuditEvent;
use crate::config::RateLimits;
use crate::routes::common::{
    ApiError, Grant, Peer, WireJson, features, ip_key, limit, now_ms, random32, sign,
};
use crate::state::AppState;
use crate::store::SessionRecord;

pub(crate) async fn exchange(
    State(state): State<AppState>,
    peer: Peer,
    WireJson(req): WireJson<ExchangeRequest>,
) -> Result<Json<Envelope>, ApiError> {
    req.validate().map_err(ApiError::bad_request)?;
    let limits = state.inner.rate_limits;
    limit(&state, &ip_key("exchange", peer.ip), limits.exchange_per_ip).await?;
    let store = &state.inner.store;
    let epoch = store
        .account_epoch(&req.account)
        .await
        .map_err(ApiError::backend)?;

    // A certificate that may not act for the account is charged to its
    // presenter, never to the account it named.
    if !peer.may_act_for(&state, &req.account).await? {
        let limiter = &state.inner.limiter;
        let presenter = peer.presenter_key("exchange:presenter");
        let within = limiter
            .check(
                &presenter,
                limits.exchange_failures_per_account,
                state.inner.rate_limits.window,
            )
            .await;
        if !within {
            return Err(denied(&state, &req.account, ErrorCode::RateLimited));
        }
        // Same cost as a real verify, so the response time says nothing.
        state
            .inner
            .verifier
            .verify(None, &req.secret)
            .await
            .map_err(ApiError::backend)?;
        return Err(denied(&state, &req.account, ErrorCode::InvalidCredentials));
    }

    let attempt = match Attempt::begin(&state, &peer, &req.account).await {
        Ok(attempt) => attempt,
        Err(reason) => return Err(denied(&state, &req.account, reason)),
    };
    let authenticated = state
        .inner
        .entitlements
        .authenticate(&req.account, &req.secret)
        .await;
    let authenticated = match authenticated {
        Ok(identity) => identity.is_some(),
        Err(e) => {
            attempt.release(&state).await;
            return Err(ApiError::backend(e));
        }
    };
    if !authenticated {
        attempt.fail(&state).await;
        return Err(denied(&state, &req.account, ErrorCode::InvalidCredentials));
    }
    attempt.release(&state).await;

    let now = now_ms();
    let grant = state
        .inner
        .entitlements
        .entitlement(&req.account, &req.product)
        .await
        .map_err(ApiError::backend)?
        .filter(|grant| now < grant.expires_at);
    let Some(grant) = grant else {
        return Err(denied(&state, &req.account, ErrorCode::NoEntitlement));
    };

    let hwid_hash: [u8; 32] = Sha256::digest(req.hwid).into();
    if state.hwid_anomaly(&req.account, hwid_hash, now) {
        state.audit(AuditEvent::HwidAnomaly {
            account: req.account.clone(),
        });
    }

    let session_id = Uuid::new_v4();
    let session_key = Zeroizing::new(random32());
    let lease = Lease {
        session_id,
        granted_at: now,
        expires_at: std::cmp::min(now + state.inner.lease_ttl, grant.expires_at),
        grace_period: state.inner.grace_period,
    };
    store
        .insert(SessionRecord {
            session_id,
            account: req.account.clone(),
            product: req.product.clone(),
            parent: None,
            hwid_hash,
            session_key: session_key.clone(),
            cert_sha256: peer.cert_sha256(),
            grant_expires_at: grant.expires_at,
            lease: lease.clone(),
            dead: None,
        })
        .await
        .map_err(ApiError::backend)?;
    // An account revocation that ran while this login was in flight wins.
    let current = store
        .account_epoch(&req.account)
        .await
        .map_err(ApiError::backend)?;
    if current != epoch {
        state
            .kill(&session_id, DeadReason::Revoked)
            .await
            .map_err(ApiError::from_server)?;
        return Err(denied(&state, &req.account, ErrorCode::SessionRevoked));
    }
    state.audit(AuditEvent::ExchangeSucceeded {
        account: req.account.clone(),
        product: req.product.clone(),
        session_id,
    });

    sign(
        &state,
        Grant {
            challenge: req.challenge,
            session_id,
            audience: AUDIENCE_CLIENT,
            operation: OP_EXCHANGE,
            issued_at: now,
            expires_at: lease.expires_at,
            body: &ExchangeBody {
                session_id,
                session_key,
                lease: lease.clone(),
                features: features(&grant),
                server_time: now,
                revoked_key_ids: state.revoked_key_ids(),
            },
        },
    )
}

fn denied(state: &AppState, account: &str, reason: ErrorCode) -> ApiError {
    state.audit(AuditEvent::ExchangeDenied {
        account: account.to_string(),
        reason,
    });
    let message = match reason {
        ErrorCode::RateLimited => "too many failed logins",
        ErrorCode::NoEntitlement => "no entitlement for product",
        ErrorCode::SessionRevoked => "account revoked",
        _ => "invalid credentials",
    };
    ApiError::new(reason, message)
}

/// How long a login waits for other in-flight attempts on the same account
/// to finish before it is refused.
const ATTEMPT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// Pause between admission retries while other attempts are in flight.
const ATTEMPT_RETRY: std::time::Duration = std::time::Duration::from_millis(10);
/// In-flight attempts one account may have queued, as a multiple of its
/// failure limit.
const IN_FLIGHT_FACTOR: u32 = 4;

/// Failure buckets for a login: per account under mTLS (only certificates
/// naming the account get here), otherwise per (account, client /64) plus an
/// account-wide ceiling.
fn failure_buckets(peer: &Peer, account: &str, limits: &RateLimits) -> Vec<(String, u32)> {
    let account_key = format!("exchange:failures:{}:{account}", account.len());
    if peer.certs.is_some() {
        return vec![(account_key, limits.exchange_failures_per_account)];
    }
    vec![
        (
            ip_key(&account_key, peer.ip),
            limits.exchange_failures_per_account,
        ),
        (
            format!("{account_key}:total"),
            limits.exchange_failures_per_account_total,
        ),
    ]
}

/// One password check's claim on the account's limits.
///
/// Each failure bucket has two counters: `slots` holds committed failures
/// plus evaluations in flight, and `committed` holds failures only. An
/// evaluation starts only with a free slot in every bucket, so failures can
/// never exceed the limit even when guesses are concurrent. When the slots
/// are taken by in-flight attempts rather than failures, the attempt waits
/// instead of being refused, so simultaneous correct logins all succeed.
struct Attempt {
    in_flight: String,
    buckets: Vec<(String, u32)>,
}

impl Attempt {
    async fn begin(state: &AppState, peer: &Peer, account: &str) -> Result<Self, ErrorCode> {
        let limits = state.inner.rate_limits;
        let limiter = &state.inner.limiter;
        let in_flight = format!("exchange:inflight:{}:{account}", account.len());
        let queue = limits
            .exchange_failures_per_account
            .saturating_mul(IN_FLIGHT_FACTOR);
        if !limiter.check(&in_flight, queue, limits.window).await {
            return Err(ErrorCode::RateLimited);
        }
        let attempt = Self {
            in_flight,
            buckets: failure_buckets(peer, account, &limits),
        };
        let deadline = tokio::time::Instant::now() + ATTEMPT_WAIT;
        loop {
            if attempt.reserve_slots(state).await {
                return Ok(attempt);
            }
            if attempt.failures_exhausted(state).await || tokio::time::Instant::now() >= deadline {
                limiter.refund(&attempt.in_flight).await;
                return Err(ErrorCode::RateLimited);
            }
            tokio::time::sleep(ATTEMPT_RETRY).await;
        }
    }

    /// Take one slot in every bucket, or none.
    async fn reserve_slots(&self, state: &AppState) -> bool {
        let limiter = &state.inner.limiter;
        let window = state.inner.rate_limits.window;
        for (taken, (key, per_window)) in self.buckets.iter().enumerate() {
            if !limiter.check(key, *per_window, window).await {
                for (key, _) in &self.buckets[..taken] {
                    limiter.refund(key).await;
                }
                return false;
            }
        }
        true
    }

    /// Whether some bucket is full of committed failures, not in-flight work.
    async fn failures_exhausted(&self, state: &AppState) -> bool {
        let window = state.inner.rate_limits.window;
        for (key, per_window) in &self.buckets {
            if !state
                .inner
                .limiter
                .peek(&committed(key), *per_window, window)
                .await
            {
                return true;
            }
        }
        false
    }

    /// The check failed: its slots stay taken and count as failures.
    async fn fail(self, state: &AppState) {
        let window = state.inner.rate_limits.window;
        for (key, per_window) in &self.buckets {
            state
                .inner
                .limiter
                .check(&committed(key), *per_window, window)
                .await;
        }
        state.inner.limiter.refund(&self.in_flight).await;
    }

    /// The check succeeded or never ran: give every slot back.
    async fn release(self, state: &AppState) {
        for (key, _) in &self.buckets {
            state.inner.limiter.refund(key).await;
        }
        state.inner.limiter.refund(&self.in_flight).await;
    }
}

fn committed(key: &str) -> String {
    format!("{key}:committed")
}
