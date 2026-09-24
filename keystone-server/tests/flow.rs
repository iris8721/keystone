//! Exchange and heartbeat against the public router: grants, verdict codes,
//! replay, concurrency, protocol gating, and restart behavior.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use common::*;
use keystone_core::DeadReason;
use keystone_core::REQUEST_SKEW;
use keystone_core::wire::{ErrorCode, PROTOCOL_HEADER};
use keystone_server::{SessionStore, public_router};

#[tokio::test]
async fn exchange_and_heartbeat_carry_the_live_grant() {
    let h = harness().await;
    let (session, body) = exchange_with(&h, exchange_req(ACCOUNT, SECRET, PRODUCT)).await;
    assert_eq!(body.features.len(), 1);
    assert_eq!(body.features[0].feature, "all");
    assert!(body.lease.expires_at > Utc::now());

    let later = Utc::now() + Duration::days(90);
    h.source
        .set_grants(ACCOUNT, vec![grant(PRODUCT, later, &["all", "beta"])]);
    let lease = heartbeat_ok(&h, &session).await;
    let names: Vec<_> = lease.features.iter().map(|f| f.feature.as_str()).collect();
    assert_eq!(names, ["all", "beta"]);
    assert_eq!(
        lease.features[0].expires_at.timestamp_millis(),
        later.timestamp_millis()
    );
    assert!(lease.lease.granted_at >= body.lease.granted_at);
}

#[tokio::test]
async fn bad_credentials_are_invalid_credentials() {
    let h = harness().await;
    let (status, body) = post(
        &h.app,
        "/exchange",
        &exchange_req(ACCOUNT, "wrong", PRODUCT),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code(&body), ErrorCode::InvalidCredentials);
}

#[tokio::test]
async fn product_without_grant_is_no_entitlement() {
    let h = harness().await;
    let (status, body) = post(
        &h.app,
        "/exchange",
        &exchange_req(ACCOUNT, SECRET, OTHER_PRODUCT),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), ErrorCode::NoEntitlement);
}

#[tokio::test]
async fn expired_grant_cannot_exchange() {
    let h = harness().await;
    h.source.set_grants(
        ACCOUNT,
        vec![grant(PRODUCT, Utc::now() - Duration::seconds(1), &["all"])],
    );
    let (status, body) = post(&h.app, "/exchange", &exchange_req(ACCOUNT, SECRET, PRODUCT)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), ErrorCode::NoEntitlement);
}

#[tokio::test]
async fn grant_lapsing_mid_session_expires_it() {
    let h = harness().await;
    let session = exchange(&h).await;
    h.source.set_grants(
        ACCOUNT,
        vec![grant(PRODUCT, Utc::now() - Duration::seconds(1), &["all"])],
    );
    for _ in 0..2 {
        let (status, body) = heartbeat(&h, &session).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(code(&body), ErrorCode::SessionExpired);
    }
}

#[tokio::test]
async fn pulled_grant_revokes_the_session() {
    let h = harness().await;
    let session = exchange(&h).await;
    h.source.set_grants(ACCOUNT, vec![]);
    let (status, body) = heartbeat(&h, &session).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), ErrorCode::NoEntitlement);

    h.source.set_grants(
        ACCOUNT,
        vec![grant(PRODUCT, Utc::now() + Duration::days(1), &["all"])],
    );
    let (status, body) = heartbeat(&h, &session).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), ErrorCode::SessionRevoked);
}

#[tokio::test]
async fn unknown_session_is_unknown_session() {
    let h = harness().await;
    let stranger = Session {
        id: uuid::Uuid::new_v4(),
        key: [9u8; 32],
    };
    let (status, body) = heartbeat(&h, &stranger).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), ErrorCode::UnknownSession);
}

#[tokio::test]
async fn restart_reports_old_sessions_as_unknown() {
    let h = harness().await;
    let session = exchange(&h).await;
    heartbeat_ok(&h, &session).await;

    let restarted = h.restarted().await;
    let (status, body) = heartbeat(&restarted, &session).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), ErrorCode::UnknownSession);
    let fresh = exchange(&restarted).await;
    heartbeat_ok(&restarted, &fresh).await;
}

#[tokio::test]
async fn protocol_header_is_required_on_both_routers() {
    let h = harness().await;
    let admin = h.admin_app();
    let body = serde_json::to_vec(&exchange_req(ACCOUNT, SECRET, PRODUCT)).unwrap();
    for (app, path) in [(&h.app, "/exchange"), (&admin, "/revoke")] {
        for header in [None, Some("1"), Some("3"), Some("two")] {
            let mut req = Request::post(path).header("content-type", "application/json");
            if let Some(value) = header {
                req = req.header(PROTOCOL_HEADER, value);
            }
            let (status, bytes) = send(app, req.body(Body::from(body.clone())).unwrap()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path} {header:?}");
            assert_eq!(code_bytes(&bytes), ErrorCode::UnsupportedProtocol);
        }
    }
}

#[tokio::test]
async fn router_without_connect_info_fails_closed() {
    let h = harness().await;
    let bare = public_router(h.state.clone());
    let (status, body) = post(&bare, "/exchange", &exchange_req(ACCOUNT, SECRET, PRODUCT)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Unknown)
    );
    assert_eq!(h.source.authentications(), 0);
}

#[tokio::test]
async fn required_client_certificates_fail_closed() {
    let h = harness_with(TestSource::standard(), |b| {
        b.require_client_certificates(true)
    })
    .await;
    let (status, body) = post(&h.app, "/exchange", &exchange_req(ACCOUNT, SECRET, PRODUCT)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Unknown)
    );
    assert_eq!(h.source.authentications(), 0);
}

#[tokio::test]
async fn exchange_racing_an_account_revocation_is_revoked() {
    let store = Arc::new(HookStore::default());
    let h = harness_with(TestSource::standard(), |b| b.session_store(store.clone())).await;
    store.bump_epoch_on_insert.store(true, Ordering::SeqCst);
    let (status, body) = post(&h.app, "/exchange", &exchange_req(ACCOUNT, SECRET, PRODUCT)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
    );
    let ids = store.ids_for_account(ACCOUNT).await.unwrap();
    assert_eq!(ids.len(), 1);
    let (record, _) = store.get(&ids[0]).await.unwrap().unwrap();
    assert_eq!(record.dead, Some(DeadReason::Revoked));

    store.bump_epoch_on_insert.store(false, Ordering::SeqCst);
    exchange(&h).await;
}

#[tokio::test]
async fn oversized_body_is_refused() {
    let h = harness().await;
    let mut req = exchange_req(ACCOUNT, SECRET, PRODUCT);
    req.secret = zeroize::Zeroizing::new("x".repeat(17 * 1024));
    let (status, body) = post(&h.app, "/exchange", &req).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(code(&body), ErrorCode::BadRequest);
}

#[tokio::test]
async fn validation_runs_before_the_backend() {
    let h = harness().await;
    h.source.set_down(true);
    let overlong = "a".repeat(keystone_core::wire::MAX_ACCOUNT_LEN + 1);
    let (status, body) = post(
        &h.app,
        "/exchange",
        &exchange_req(&overlong, SECRET, PRODUCT),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&body), ErrorCode::BadRequest);

    let (status, body) = post(
        &h.app,
        "/exchange",
        &exchange_req(ACCOUNT, SECRET, "../etc"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(code(&body), ErrorCode::BadRequest);
}

#[tokio::test]
async fn malformed_json_is_a_bad_request_body() {
    let h = harness().await;
    let req = Request::post("/heartbeat")
        .header("content-type", "application/json")
        .header(PROTOCOL_HEADER, "2")
        .body(Body::from("{\"session_id\": 5"))
        .unwrap();
    let (status, bytes) = send(&h.app, req).await;
    assert!(status.is_client_error());
    assert_eq!(code_bytes(&bytes), ErrorCode::BadRequest);
}

#[tokio::test]
async fn backend_outage_is_transient_and_spares_the_session() {
    let h = harness().await;
    let session = exchange(&h).await;
    h.source.set_down(true);
    let (status, body) = heartbeat(&h, &session).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(code(&body), ErrorCode::BackendUnavailable);
    h.source.set_down(false);
    heartbeat_ok(&h, &session).await;
}

#[tokio::test]
async fn bad_mac_and_stale_timestamp_are_rejected() {
    let h = harness().await;
    let session = exchange(&h).await;
    let forged = Session {
        id: session.id,
        key: [0u8; 32],
    };
    let (status, body) = heartbeat(&h, &forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code(&body), ErrorCode::InvalidMac);

    let stale = now_ms() - REQUEST_SKEW - Duration::seconds(1);
    let (status, body) = post(
        &h.app,
        "/heartbeat",
        &heartbeat_req(&session, nonce(), stale),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code(&body), ErrorCode::StaleRequest);
    heartbeat_ok(&h, &session).await;
}

#[tokio::test]
async fn reused_heartbeat_is_a_replay() {
    let h = harness().await;
    let session = exchange(&h).await;
    let req = heartbeat_req(&session, nonce(), now_ms());
    let (status, _) = post(&h.app, "/heartbeat", &req).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post(&h.app, "/heartbeat", &req).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(code(&body), ErrorCode::Replay);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_replays_have_exactly_one_winner() {
    let h = harness().await;
    let session = exchange(&h).await;
    let req = heartbeat_req(&session, nonce(), now_ms());
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let app = h.app.clone();
            let req = req.clone();
            tokio::spawn(async move { post(&app, "/heartbeat", &req).await })
        })
        .collect();
    let mut ok = 0;
    for task in tasks {
        let (status, body) = task.await.unwrap();
        if status == StatusCode::OK {
            ok += 1;
        } else {
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(code(&body), ErrorCode::Replay);
        }
    }
    assert_eq!(ok, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_distinct_heartbeats_all_succeed() {
    let h = harness().await;
    let session = exchange(&h).await;
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let app = h.app.clone();
            let req = heartbeat_req(&session, nonce(), now_ms());
            tokio::spawn(async move { post(&app, "/heartbeat", &req).await })
        })
        .collect();
    for task in tasks {
        let (status, body) = task.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

#[tokio::test]
async fn revoked_session_stays_revoked() {
    let h = harness().await;
    let session = exchange(&h).await;
    let other = exchange(&h).await;
    assert_eq!(h.state.revoke_session(session.id).await.unwrap(), 1);
    assert_eq!(h.state.revoke_session(session.id).await.unwrap(), 0);
    let (status, body) = heartbeat(&h, &session).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code(&body), ErrorCode::SessionRevoked);
    heartbeat_ok(&h, &other).await;
}

#[tokio::test]
async fn expired_records_survive_requests_until_swept() {
    let h = harness_with(TestSource::standard(), |b| {
        b.lease_ttl(Duration::milliseconds(300))
            .grace_period(Duration::zero())
    })
    .await;
    let session = exchange(&h).await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    // Requests do not sweep: the lapsed session still answers as expired.
    for _ in 0..2 {
        let (status, body) = heartbeat(&h, &session).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(code(&body), ErrorCode::SessionExpired);
    }
    assert_eq!(h.state.sweep().await.unwrap(), 1);
    let (status, body) = heartbeat(&h, &session).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), ErrorCode::UnknownSession);
}

#[tokio::test]
async fn unknown_route_is_a_wire_error() {
    let h = harness().await;
    let (status, body) = post(&h.app, "/revoke", &serde_json::json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(code(&body), ErrorCode::BadRequest);
}
