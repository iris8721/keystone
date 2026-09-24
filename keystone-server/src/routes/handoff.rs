//! `POST /handoff`: a live session mints a single-use credential for a
//! child process.

use axum::extract::State;
use axum::response::Json;
use keystone_core::Envelope;
use keystone_core::wire::{
    AUDIENCE_CLIENT, ErrorCode, HandoffBody, HandoffRequest, OP_HANDOFF, mac_context,
};
use zeroize::Zeroizing;

use crate::audit::AuditEvent;
use crate::routes::common::{
    ApiError, Grant, Peer, SessionProof, WireJson, authorize_session, consume_nonce, now_ms,
    random32, sign,
};
use crate::state::AppState;
use crate::store::HandoffRecord;

/// Unredeemed, unexpired handoffs one session may hold at once.
pub(crate) const MAX_OUTSTANDING_HANDOFFS: usize = 4;

pub(crate) async fn handoff(
    State(state): State<AppState>,
    peer: Peer,
    WireJson(req): WireJson<HandoffRequest>,
) -> Result<Json<Envelope>, ApiError> {
    req.validate().map_err(ApiError::bad_request)?;
    let context = mac_context::handoff(&req.process_id, req.ttl_millis);
    let parent = authorize_session(
        &state,
        &peer,
        SessionProof {
            route: "handoff",
            per_session: state.inner.rate_limits.handoff_per_session,
            session_id: &req.session_id,
            nonce: &req.nonce,
            issued_at: req.issued_at,
            mac: &req.mac,
            context: &context,
        },
    )
    .await?;
    consume_nonce(&state, &req.session_id, &req.nonce, req.issued_at).await?;

    let now = now_ms();
    let handoff_id = random32();
    let secret = Zeroizing::new(random32());
    let expires_at = now + req.ttl();
    let stored = state
        .inner
        .store
        .insert_handoff(
            HandoffRecord {
                handoff_id,
                secret: secret.clone(),
                parent: parent.session_id,
                process_id: req.process_id.clone(),
                account: parent.account.clone(),
                product: parent.product.clone(),
                expires_at,
            },
            MAX_OUTSTANDING_HANDOFFS,
        )
        .await
        .map_err(ApiError::backend)?;
    if !stored {
        return Err(ApiError::new(
            ErrorCode::RateLimited,
            "too many outstanding handoffs",
        ));
    }
    state.audit(AuditEvent::HandoffCreated {
        parent: parent.session_id,
    });

    sign(
        &state,
        Grant {
            challenge: req.nonce,
            session_id: parent.session_id,
            audience: AUDIENCE_CLIENT,
            operation: OP_HANDOFF,
            issued_at: now,
            expires_at,
            body: &HandoffBody {
                handoff_id,
                handoff_secret: secret,
                expires_at,
                server_time: now,
                revoked_key_ids: state.revoked_key_ids(),
            },
        },
    )
}
