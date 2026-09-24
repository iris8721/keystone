//! `POST /heartbeat`: renew a live session's lease against its live grant.

use axum::extract::State;
use axum::response::Json;
use keystone_core::wire::{
    AUDIENCE_CLIENT, HeartbeatRequest, LeaseBody, OP_HEARTBEAT, mac_context,
};
use keystone_core::{Envelope, Lease};

use crate::routes::common::{
    ApiError, Grant, Peer, SessionProof, WireJson, authorize_session, consume_nonce, features,
    live_grant, now_ms, sign, update_session,
};
use crate::state::AppState;

pub(crate) async fn heartbeat(
    State(state): State<AppState>,
    peer: Peer,
    WireJson(req): WireJson<HeartbeatRequest>,
) -> Result<Json<Envelope>, ApiError> {
    req.validate().map_err(ApiError::bad_request)?;
    let context = mac_context::heartbeat();
    let record = authorize_session(
        &state,
        &peer,
        SessionProof {
            route: "heartbeat",
            per_session: state.inner.rate_limits.heartbeat_per_session,
            session_id: &req.session_id,
            nonce: &req.nonce,
            issued_at: req.issued_at,
            mac: &req.mac,
            context: &context,
        },
    )
    .await?;
    consume_nonce(&state, &req.session_id, &req.nonce, req.issued_at).await?;
    let grant = live_grant(&state, &record).await?;

    let now = now_ms();
    let lease = Lease {
        session_id: req.session_id,
        granted_at: now,
        expires_at: std::cmp::min(now + state.inner.lease_ttl, grant.expires_at),
        grace_period: state.inner.grace_period,
    };
    update_session(&state, &req.session_id, |record| {
        record.lease = lease.clone();
        record.grant_expires_at = grant.expires_at;
        Ok(())
    })
    .await?;

    sign(
        &state,
        Grant {
            challenge: req.nonce,
            session_id: req.session_id,
            audience: AUDIENCE_CLIENT,
            operation: OP_HEARTBEAT,
            issued_at: now,
            expires_at: lease.expires_at,
            body: &LeaseBody {
                lease: lease.clone(),
                features: features(&grant),
                server_time: now,
                revoked_key_ids: state.revoked_key_ids(),
            },
        },
    )
}
