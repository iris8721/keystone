//! `POST /attest`: a child process redeems a handoff for its own session.

use axum::extract::State;
use axum::response::Json;
use chrono::Utc;
use keystone_core::wire::{
    AUDIENCE_APP, AttestBody, AttestRequest, ErrorCode, OP_ATTEST, mac_context,
};
use keystone_core::{
    DeadReason, Envelope, Lease, RequestBinding, check_request_freshness, handoff_wrap_key,
    verify_request_mac, wrap_secret,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::AuditEvent;
use crate::routes::common::{
    ApiError, Grant, Peer, WireJson, features, ip_key, limit, live_grant, now_ms, random32, sign,
};
use crate::state::AppState;
use crate::store::{HandoffRecord, SessionRecord};

fn invalid() -> ApiError {
    ApiError::new(ErrorCode::HandoffInvalid, "handoff is invalid")
}

pub(crate) async fn attest(
    State(state): State<AppState>,
    peer: Peer,
    WireJson(req): WireJson<AttestRequest>,
) -> Result<Json<Envelope>, ApiError> {
    req.validate().map_err(ApiError::bad_request)?;
    let limits = state.inner.rate_limits;
    limit(&state, &ip_key("session", peer.ip), limits.session_per_ip).await?;
    check_request_freshness(req.issued_at, Utc::now()).map_err(|_| {
        ApiError::new(
            ErrorCode::StaleRequest,
            "request timestamp outside the acceptance window",
        )
    })?;
    let store = &state.inner.store;
    let (parent, _) = store
        .get(&req.parent_session_id)
        .await
        .map_err(ApiError::backend)?
        .ok_or_else(invalid)?;
    if parent.dead.is_some() {
        return Err(invalid());
    }
    // A lapsed parent lease ends the parent here, as any other route would.
    if parent.lease.is_expired(Utc::now()) {
        state
            .kill(&parent.session_id, DeadReason::Expired)
            .await
            .map_err(ApiError::from_server)?;
        return Err(invalid());
    }
    // Resolve the grant before spending the handoff: an outage leaves it redeemable.
    let grant = live_grant(&state, &parent).await?;
    // Reserve the parent's slot before spending the handoff, so a full bucket
    // never costs a handoff; only a caller holding the handoff secret keeps it.
    let bucket = format!("attest:session:{}", parent.session_id);
    limit(&state, &bucket, limits.attest_per_session).await?;
    let verified = redeem(&state, &req).await;
    let handoff = match verified {
        Ok(handoff) => handoff,
        Err(e) => {
            state.inner.limiter.refund(&bucket).await;
            return Err(e);
        }
    };
    let now = now_ms();
    if !peer.may_act_for(&state, &handoff.account).await? {
        return Err(ApiError::new(
            ErrorCode::InvalidCredentials,
            "client certificate does not match the account",
        ));
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
            account: handoff.account.clone(),
            product: handoff.product.clone(),
            parent: Some(parent.session_id),
            hwid_hash: parent.hwid_hash,
            session_key: session_key.clone(),
            cert_sha256: peer.cert_sha256(),
            grant_expires_at: grant.expires_at,
            lease: lease.clone(),
            dead: None,
        })
        .await
        .map_err(ApiError::backend)?;
    // A revocation that raced the insert must not miss the new child.
    let parent_alive = store
        .get(&parent.session_id)
        .await
        .map_err(ApiError::backend)?
        .is_some_and(|(p, _)| p.dead.is_none());
    if !parent_alive {
        state
            .kill(&session_id, DeadReason::Revoked)
            .await
            .map_err(ApiError::from_server)?;
        return Err(invalid());
    }
    state.audit(AuditEvent::AttestSucceeded {
        session_id,
        parent: parent.session_id,
    });

    let wrap_key = handoff_wrap_key(&handoff.secret, &req.challenge);
    sign(
        &state,
        Grant {
            challenge: req.challenge,
            session_id,
            audience: AUDIENCE_APP,
            operation: OP_ATTEST,
            issued_at: now,
            expires_at: lease.expires_at,
            body: &AttestBody {
                session_id,
                session_key_wrap: wrap_secret(&wrap_key, &session_key),
                lease: lease.clone(),
                features: features(&grant),
                server_time: now,
                revoked_key_ids: state.revoked_key_ids(),
            },
        },
    )
}

/// Take the handoff and check it belongs to this request and its MAC holds.
async fn redeem(state: &AppState, req: &AttestRequest) -> Result<HandoffRecord, ApiError> {
    let handoff = state
        .inner
        .store
        .take_handoff(&req.handoff_id)
        .await
        .map_err(ApiError::backend)?
        .ok_or_else(invalid)?;
    if handoff.parent != req.parent_session_id
        || handoff.process_id != req.process_id
        || handoff.expires_at <= now_ms()
    {
        return Err(invalid());
    }
    verify_request_mac(
        &handoff.secret[..],
        &RequestBinding {
            session_id: &req.parent_session_id,
            nonce: &req.challenge,
            issued_at: req.issued_at,
            context: &mac_context::attest(&req.handoff_id, &req.process_id),
        },
        &req.mac,
    )
    .map_err(|_| invalid())?;
    Ok(handoff)
}
