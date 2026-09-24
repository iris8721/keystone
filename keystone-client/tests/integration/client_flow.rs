//! Session lifecycle against a real server over mTLS: exchange, gate,
//! heartbeat and keepalive, revocation, restart, clock skew, and stray
//! non-keystone errors.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration as StdDuration;
use std::time::Instant;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use chrono::{Duration, Utc};
use keystone_client::{ClientError, DEFAULT_HANDOFF_TTL, DeadReason, ErrorCode, FeatureGrant};
use keystone_core::wire::{
    ExchangeBody, HeartbeatRequest, LeaseBody, PROTOCOL_HEADER, PROTOCOL_VERSION, mac_context,
    paths,
};
use keystone_core::{
    Envelope, IssueSpec, Issuer, Lease, RequestBinding, mac_request, verify_request_mac,
};
use parking_lot::Mutex;
use serde::Serialize;
use uuid::Uuid;

use crate::common::*;

fn feature_names(features: &[FeatureGrant]) -> Vec<&str> {
    features.iter().map(|f| f.feature.as_str()).collect()
}

fn rejection(err: &ClientError) -> (u16, Option<ErrorCode>) {
    match err {
        ClientError::ServerRejected { status, code, .. } => (*status, *code),
        other => panic!("expected a server rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn exchange_opens_the_gate_and_heartbeat_renews_lease_and_features() {
    let rig = rig().await;
    let client = rig.client();
    let session = rig.exchange(&client).await;
    let gate = session.gate();
    gate.authorize().expect("fresh session authorizes");
    assert!(gate.has_feature("all"));
    assert!(!gate.has_feature("beta"));
    let first_due = session.next_heartbeat_due().expect("live session is due");

    rig.source.set_grants(vec![grant(PRODUCT, &["beta"])]);
    tokio::time::sleep(StdDuration::from_millis(50)).await;
    client.heartbeat(&session).await.expect("heartbeat");

    assert_eq!(feature_names(&session.features()), ["beta"]);
    assert!(gate.has_feature("beta"));
    assert!(!gate.has_feature("all"));
    assert!(
        session.next_heartbeat_due().unwrap() > first_due,
        "renewal pushes the next heartbeat out"
    );
    gate.authorize().expect("renewed session authorizes");
}

#[tokio::test]
async fn keepalive_renews_while_clones_keep_working_until_revoked() {
    let rig = rig_with(|b| b.lease_ttl(Duration::seconds(8))).await;
    let client = rig.client();
    let session = rig.exchange(&client).await;
    let gate = session.gate();
    let first_due = session.next_heartbeat_due().expect("live session is due");
    let keepalive = tokio::spawn({
        let client = client.clone();
        let session = session.clone();
        async move { client.run_keepalive(&session).await }
    });

    // The loader keeps using its session while keepalive holds a clone.
    client
        .create_handoff(&session, PROCESS_ID, DEFAULT_HANDOFF_TTL)
        .await
        .expect("handoff while keepalive runs");

    let deadline = Instant::now() + StdDuration::from_secs(20);
    while session.next_heartbeat_due().expect("session stays alive") <= first_due {
        assert!(Instant::now() < deadline, "keepalive never renewed");
        tokio::time::sleep(StdDuration::from_millis(100)).await;
    }
    assert!(gate.is_alive());

    let revoked = rig.admin().revoke_account(ACCOUNT).await.unwrap();
    assert_eq!(revoked.revoked, 1);
    let reason = tokio::time::timeout(StdDuration::from_secs(20), keepalive)
        .await
        .expect("keepalive ends after the revocation")
        .unwrap();
    assert_eq!(reason, DeadReason::Revoked);
    assert_eq!(gate.dead_reason(), Some(DeadReason::Revoked));
    assert!(!gate.has_feature("all"));
}

#[tokio::test]
async fn gate_on_another_thread_sees_the_kill_immediately() {
    let rig = rig().await;
    let client = rig.client();
    let session = rig.exchange(&client).await;
    let gate = session.gate();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let watcher = std::thread::spawn(move || {
        gate.authorize().expect("open before the kill");
        ready_tx.send(()).unwrap();
        go_rx.recv().unwrap();
        (
            gate.authorize().is_err(),
            gate.has_feature("all"),
            gate.dead_reason(),
        )
    });
    ready_rx.recv().unwrap();

    rig.admin()
        .revoke_session(session.session_id())
        .await
        .unwrap();
    let err = client.heartbeat(&session).await.unwrap_err();
    assert_eq!(rejection(&err).1, Some(ErrorCode::SessionRevoked));
    go_tx.send(()).unwrap();

    let (denied, feature, reason) = watcher.join().unwrap();
    assert!(denied);
    assert!(!feature);
    assert_eq!(reason, Some(DeadReason::Revoked));
}

#[tokio::test]
async fn restart_reports_unknown_session_not_revoked() {
    let mut rig = rig().await;
    let client = rig.client();
    let revoked = rig.exchange(&client).await;
    let orphaned = rig.exchange(&client).await;
    rig.admin()
        .revoke_session(revoked.session_id())
        .await
        .unwrap();
    let err = client.heartbeat(&revoked).await.unwrap_err();
    assert_eq!(rejection(&err).1, Some(ErrorCode::SessionRevoked));
    assert_eq!(revoked.dead_reason(), Some(DeadReason::Revoked));

    rig.restart().await;
    let client = rig.client();
    let err = client.heartbeat(&orphaned).await.unwrap_err();
    assert_eq!(rejection(&err), (404, Some(ErrorCode::UnknownSession)));
    assert!(!err.is_retryable());
    assert_eq!(orphaned.dead_reason(), Some(DeadReason::UnknownSession));
    assert!(orphaned.gate().authorize().is_err());

    // Same signing key: the restarted server's sessions verify.
    rig.exchange(&client).await;
}

#[tokio::test]
async fn codeless_404_is_retryable_and_keeps_the_session() {
    let rig = rig().await;
    let client = rig.client();
    let session = rig.exchange(&client).await;
    let front = serve_router(
        &rig.ca,
        Router::new().fallback(|| async { (StatusCode::NOT_FOUND, "not found") }),
    );
    let stray = rig.client_for(front);

    let err = stray.heartbeat(&session).await.unwrap_err();
    assert_eq!(rejection(&err), (404, None));
    assert!(err.is_retryable());
    assert!(session.is_alive(), "a code-less 404 is transient");

    let err = stray
        .create_handoff(&session, PROCESS_ID, DEFAULT_HANDOFF_TTL)
        .await
        .unwrap_err();
    assert_eq!(rejection(&err), (404, None));
    assert!(session.is_alive());

    client
        .heartbeat(&session)
        .await
        .expect("the real server still renews");
    assert!(session.gate().has_feature("all"));
}

const SKEW: Duration = Duration::seconds(600);

/// Relays `/exchange` and `/heartbeat` to the real server while presenting
/// a server clock `SKEW` ahead: responses are re-signed with shifted
/// timestamps, and request timestamps are shifted back and re-MAC'd.
#[derive(Clone)]
struct SkewProxy {
    upstream: reqwest::Client,
    base: String,
    issuer: Arc<Issuer>,
    keys: Arc<Mutex<HashMap<Uuid, [u8; 32]>>>,
    /// Each heartbeat's `issued_at` minus real time.
    stamps: Arc<Mutex<Vec<Duration>>>,
}

impl SkewProxy {
    fn new(rig: &Rig) -> Self {
        let cert = rig.ca.client_cert(ACCOUNT);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(PROTOCOL_HEADER, PROTOCOL_VERSION.into());
        let upstream = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(rig.ca.pem().as_bytes()).unwrap())
            .identity(
                reqwest::Identity::from_pem(
                    format!("{}{}", cert.cert_pem, cert.key_pem).as_bytes(),
                )
                .unwrap(),
            )
            .default_headers(headers)
            .build()
            .unwrap();
        Self {
            upstream,
            base: https_url(rig.server.public),
            issuer: Arc::new(rig.issuer()),
            keys: Arc::default(),
            stamps: Arc::default(),
        }
    }

    fn router(&self) -> Router {
        Router::new()
            .route(paths::EXCHANGE, post(skew_exchange))
            .route(paths::HEARTBEAT, post(skew_heartbeat))
            .with_state(self.clone())
    }

    async fn forward(&self, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let resp = self
            .upstream
            .post(format!("{}{path}", self.base))
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .expect("upstream reachable");
        (resp.status(), resp.bytes().await.unwrap().to_vec())
    }

    fn reissue(&self, env: &Envelope, body: &impl Serialize) -> Response {
        Json(Envelope::issue(
            &self.issuer,
            IssueSpec {
                challenge: env.challenge,
                session_id: env.session_id,
                audience: env.audience.clone(),
                operation: env.operation.clone(),
                issued_at: env.issued_at + SKEW,
                expires_at: env.expires_at + SKEW,
                body: serde_json::to_vec(body).unwrap(),
            },
        ))
        .into_response()
    }
}

fn shift(lease: &mut Lease, features: &mut [FeatureGrant]) {
    lease.granted_at += SKEW;
    lease.expires_at += SKEW;
    for grant in features {
        grant.expires_at += SKEW;
    }
}

fn relay_error(status: StatusCode, body: Vec<u8>) -> Response {
    (status, [(CONTENT_TYPE, "application/json")], body).into_response()
}

async fn skew_exchange(State(proxy): State<SkewProxy>, body: Bytes) -> Response {
    let (status, bytes) = proxy.forward(paths::EXCHANGE, body.to_vec()).await;
    if !status.is_success() {
        return relay_error(status, bytes);
    }
    let env: Envelope = serde_json::from_slice(&bytes).unwrap();
    let mut body: ExchangeBody = serde_json::from_slice(&env.body).unwrap();
    proxy.keys.lock().insert(body.session_id, *body.session_key);
    shift(&mut body.lease, &mut body.features);
    body.server_time += SKEW;
    proxy.reissue(&env, &body)
}

async fn skew_heartbeat(State(proxy): State<SkewProxy>, body: Bytes) -> Response {
    let mut req: HeartbeatRequest = serde_json::from_slice(&body).unwrap();
    let key = proxy.keys.lock()[&req.session_id];
    proxy.stamps.lock().push(req.issued_at - Utc::now());
    let context = mac_context::heartbeat();
    verify_request_mac(
        &key,
        &RequestBinding {
            session_id: &req.session_id,
            nonce: &req.nonce,
            issued_at: req.issued_at,
            context: &context,
        },
        &req.mac,
    )
    .expect("client MAC covers its own timestamp");
    req.issued_at -= SKEW;
    req.mac = mac_request(
        &key,
        &RequestBinding {
            session_id: &req.session_id,
            nonce: &req.nonce,
            issued_at: req.issued_at,
            context: &context,
        },
    );
    let (status, bytes) = proxy
        .forward(paths::HEARTBEAT, serde_json::to_vec(&req).unwrap())
        .await;
    if !status.is_success() {
        return relay_error(status, bytes);
    }
    let env: Envelope = serde_json::from_slice(&bytes).unwrap();
    let mut body: LeaseBody = serde_json::from_slice(&env.body).unwrap();
    shift(&mut body.lease, &mut body.features);
    body.server_time += SKEW;
    proxy.reissue(&env, &body)
}

#[tokio::test]
async fn server_clock_ten_minutes_ahead_still_exchanges_and_heartbeats() {
    let rig = rig().await;
    let proxy = SkewProxy::new(&rig);
    let client = rig.client_for(serve_router(&rig.ca, proxy.router()));

    let session = rig.exchange(&client).await;
    assert!(session.gate().has_feature("all"));
    for _ in 0..2 {
        client
            .heartbeat(&session)
            .await
            .expect("heartbeat stamped on the server clock is fresh");
    }
    assert!(session.is_alive());

    let stamps = proxy.stamps.lock().clone();
    assert_eq!(stamps.len(), 2);
    for stamp in stamps {
        assert!(
            (stamp - SKEW).num_seconds().abs() <= 5,
            "request stamped {stamp} from local time, expected about {SKEW}"
        );
    }
}
