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

    let reservations = reserve_failure_slots(&state, &peer, &req.account).await;
    let Some(reservations) = reservations else {
        return Err(denied(&state, &req.account, ErrorCode::RateLimited));
    };
    let authenticated = state
        .inner
        .entitlements
        .authenticate(&req.account, &req.secret)
        .await;
    let authenticated = match authenticated {
        Ok(identity) => identity.is_some(),
        Err(e) => {
            refund(&state, &reservations).await;
            return Err(ApiError::backend(e));
        }
    };
    if !authenticated {
        return Err(denied(&state, &req.account, ErrorCode::InvalidCredentials));
    }
    refund(&state, &reservations).await;

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

/// Failure buckets a login attempt reserves before the password check:
/// per account under mTLS (only certificates naming the account get here),
/// otherwise per (account, client /64) plus an account-wide ceiling.
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

/// Reserve one slot in every failure bucket, or none: `None` when any
/// bucket is full. Reserving before the check bounds concurrent guesses.
async fn reserve_failure_slots(
    state: &AppState,
    peer: &Peer,
    account: &str,
) -> Option<Vec<String>> {
    let limiter = &state.inner.limiter;
    let mut reserved = Vec::new();
    for (key, per_window) in failure_buckets(peer, account, &state.inner.rate_limits) {
        if !limiter
            .check(&key, per_window, state.inner.rate_limits.window)
            .await
        {
            refund(state, &reserved).await;
            return None;
        }
        reserved.push(key);
    }
    Some(reserved)
}

async fn refund(state: &AppState, keys: &[String]) {
    for key in keys {
        state.inner.limiter.refund(key).await;
    }
}
