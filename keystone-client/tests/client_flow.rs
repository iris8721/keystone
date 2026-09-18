//! End-to-end client tests against the real server: the router is
//! built from keystone-server and bound to an ephemeral port, so the
//! client exercises the actual wire — not a mock of it.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use axum::{Json, Router, routing::post};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use keystone_client::{ClientError, KeystoneClient};
use keystone_core::{
    DeadReason, Entitlement, Envelope, IssueSpec, Issuer, KeystoneError, Lease, TrustedIssuers,
};
use keystone_server::entitlement::StubEntitlementSource;
use keystone_server::state::{ArtifactHashes, RateLimiter, RateLimits};
use keystone_server::{AppState, SessionStore, build_router};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use uuid::Uuid;

const ACCOUNT: &str = "dev";
const SECRET: &str = "devpass";
const PRODUCT: &str = "dev-product";
const ADMIN_TOKEN: &str = "test-admin-token";
const ISSUER_SEED: [u8; 32] = [7u8; 32];
const KEY_ID: u8 = 1;

fn test_state(lease_ttl: Duration, grace_period: Duration) -> AppState {
    test_state_with_issuer(
        Issuer::from_seed(&ISSUER_SEED, KEY_ID),
        lease_ttl,
        grace_period,
    )
}

fn test_state_with_issuer(issuer: Issuer, lease_ttl: Duration, grace_period: Duration) -> AppState {
    let entitlements = Arc::new(StubEntitlementSource::new(vec![(
        ACCOUNT.to_string(),
        SECRET.to_string(),
        vec![Entitlement {
            account: ACCOUNT.to_string(),
            product: PRODUCT.to_string(),
            expires_at: Utc::now() + Duration::days(30),
            features: vec!["all".to_string()],
        }],
    )]));
    AppState {
        issuer: Arc::new(issuer),
        store: SessionStore::new(),
        entitlements,
        admin_token_hash: Some(Sha256::digest(ADMIN_TOKEN.as_bytes()).into()),
        lease_ttl,
        grace_period,
        payload_dir: None,
        payload_secret: None,
        payload_epoch: 0,
        downloads: None,
        watermark_secret: None,
        rate_limits: RateLimits::default(),
        rate_limiter: Arc::new(RateLimiter::default()),
        artifact_hashes: Arc::new(ArtifactHashes::default()),
        revoked_key_ids: Arc::new(RwLock::new(BTreeSet::new())),
    }
}

/// Serve the real router on an ephemeral port. Returns the base URL
/// and the server task so tests can kill it mid-session.
async fn spawn_server(state: AppState) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

fn pinned_key() -> VerifyingKey {
    Issuer::from_seed(&ISSUER_SEED, KEY_ID).verifying_key()
}

/// The trust set a build bakes in: the one issuer key under its id.
fn issuers() -> TrustedIssuers {
    TrustedIssuers::single(KEY_ID, pinned_key())
}

/// Tests run against a plaintext loopback server — the insecure
/// constructor exists for exactly this.
fn client_for(base_url: &str) -> KeystoneClient {
    KeystoneClient::new_insecure(base_url, issuers()).unwrap()
}

/// A client pointed at a port with nothing listening: bind, take the
/// address, drop the listener. (Killing the serve task isn't enough —
/// axum spawns per-connection tasks, so a pooled keep-alive connection
/// would keep answering after the accept loop dies.)
async fn dead_client() -> KeystoneClient {
    let dead_addr = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    KeystoneClient::new_insecure(format!("http://{dead_addr}"), issuers()).unwrap()
}

#[test]
fn new_rejects_http_base_url() {
    // Credentials and session material cross this transport — the
    // pinned constructor refuses plaintext even with full pin material.
    let res = KeystoneClient::new("http://127.0.0.1:1", issuers(), b"ca", [0u8; 32], None);
    assert!(matches!(res, Err(ClientError::InsecureBaseUrl(_))));
    let res = KeystoneClient::new_unpinned_webpki("http://127.0.0.1:1", issuers());
    assert!(matches!(res, Err(ClientError::InsecureBaseUrl(_))));
}

#[test]
fn new_unpinned_webpki_builds() {
    // The escape hatch still constructs — it just trusts public roots,
    // which its docs warn about. (The loopback test server is plain
    // http, which this constructor refuses by design.)
    KeystoneClient::new_unpinned_webpki("https://127.0.0.1:1", issuers())
        .expect("webpki constructor must build");
}

#[tokio::test]
async fn full_flow_exchange_attest_heartbeat_authorize() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);

    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");
    assert!(session.is_alive());
    assert!(session.authorize().is_ok());

    let lease = client
        .attest(&mut session, "keystone-client-test")
        .await
        .expect("attest");
    assert_eq!(lease.session_id, session.session_id());

    let renewed = client.heartbeat(&mut session).await.expect("heartbeat");
    assert_eq!(renewed.session_id, session.session_id());
    assert!(session.authorize().is_ok());
}

#[tokio::test]
async fn bad_credentials_rejected_401() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);

    let err = client
        .exchange(ACCOUNT, "wrong-secret", PRODUCT, [9u8; 32])
        .await
        .expect_err("bad credentials must fail");
    match err {
        ClientError::ServerRejected { status, .. } => assert_eq!(status, 401),
        other => panic!("expected ServerRejected, got {other:?}"),
    }
}

#[tokio::test]
async fn wrong_pinned_key_fails_verification() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    // A client pinned to a different issuer under the SAME key id must
    // reject every envelope the real server signs — the pin is the
    // whole trust model, and the id alone proves nothing.
    let wrong_key = Issuer::from_seed(&[8u8; 32], KEY_ID).verifying_key();
    let client =
        KeystoneClient::new_insecure(&base_url, TrustedIssuers::single(KEY_ID, wrong_key)).unwrap();

    let err = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect_err("envelope from an unpinned issuer must fail");
    assert!(matches!(
        err,
        ClientError::Core(KeystoneError::InvalidSignature)
    ));
}

#[tokio::test]
async fn heartbeat_after_revoke_kills_session() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);

    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");
    client
        .revoke(session.session_id(), ADMIN_TOKEN)
        .await
        .expect("revoke");

    let err = client
        .heartbeat(&mut session)
        .await
        .expect_err("heartbeat on a revoked session must fail");
    assert!(matches!(
        err,
        ClientError::ServerRejected { status: 403, .. }
    ));
    assert!(!session.is_alive());
    assert!(matches!(
        session.authorize(),
        Err(ClientError::Core(KeystoneError::Revoked))
    ));
}

#[tokio::test]
async fn heartbeat_unknown_session_kills() {
    let state = test_state(Duration::seconds(300), Duration::seconds(60));
    let (base_url, _server) = spawn_server(state.clone()).await;
    let client = client_for(&base_url);

    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");

    // Make the server forget the session: kill the record and age it
    // past its entitlement so the sweep middleware drops it — the next
    // heartbeat then sees 404, not 403.
    state.store.with_mut(&session.session_id(), |rec| {
        rec.state.kill(DeadReason::Rejected);
        rec.entitlement_expires_at = Utc::now() - Duration::seconds(1);
    });

    let err = client
        .heartbeat(&mut session)
        .await
        .expect_err("heartbeat on a forgotten session must fail");
    assert!(matches!(
        err,
        ClientError::ServerRejected { status: 404, .. }
    ));
    // Gone is a verdict, not a transient loss — no grace.
    assert!(!session.is_alive());
    assert!(session.authorize().is_err());
}

#[tokio::test]
async fn heartbeat_bad_mac_kills() {
    let state = test_state(Duration::seconds(300), Duration::seconds(60));
    let (base_url, _server) = spawn_server(state.clone()).await;
    let client = client_for(&base_url);

    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");

    // Corrupt the server-side key so the client's MAC can never
    // verify — the server answers 401, which is hopeless to retry.
    state.store.with_mut(&session.session_id(), |rec| {
        rec.session_key = [0xEE; 32];
    });

    let err = client
        .heartbeat(&mut session)
        .await
        .expect_err("heartbeat with an unverifiable MAC must fail");
    assert!(matches!(
        err,
        ClientError::ServerRejected { status: 401, .. }
    ));
    assert!(!session.is_alive());
}

#[tokio::test]
async fn forged_heartbeat_response_enters_grace() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");

    // A rogue endpoint that answers /heartbeat with an envelope signed
    // by the wrong issuer — well-formed, but unverifiable.
    async fn rogue_heartbeat() -> Json<Value> {
        let rogue_issuer = Issuer::from_seed(&[0xEE; 32], 1);
        let env = Envelope::issue(
            &rogue_issuer,
            IssueSpec {
                challenge: [0u8; 32],
                session_id: Uuid::nil(),
                audience: "keystone-client".into(),
                operation: "session.heartbeat".into(),
                issued_at: Utc::now(),
                expires_at: Utc::now() + Duration::seconds(60),
                body: b"{}".to_vec(),
            },
        );
        Json(serde_json::to_value(env).unwrap())
    }
    let rogue = Router::new().route("/heartbeat", post(rogue_heartbeat));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, rogue).await.unwrap();
    });
    let rogue_client = KeystoneClient::new_insecure(format!("http://{addr}"), issuers()).unwrap();

    let err = rogue_client
        .heartbeat(&mut session)
        .await
        .expect_err("a forged heartbeat must fail verification");
    assert!(matches!(err, ClientError::Core(_)));
    // Active tampering is no more lenient than silence: the session
    // enters grace and the lease still authorizes inside it.
    assert!(session.is_alive());
    assert!(session.authorize().is_ok());
}

#[tokio::test]
async fn attest_after_revoke_kills_session() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);

    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");
    client
        .revoke(session.session_id(), ADMIN_TOKEN)
        .await
        .expect("revoke");

    let err = client
        .attest(&mut session, "keystone-client-test")
        .await
        .expect_err("attest on a revoked session must fail");
    assert!(matches!(
        err,
        ClientError::ServerRejected { status: 403, .. }
    ));
    // An explicit rejection must not leave the local lease authorizing.
    assert!(!session.is_alive());
    assert!(session.authorize().is_err());
}

#[tokio::test]
async fn dead_server_enters_grace_then_exhausts() {
    let grace = Duration::seconds(2);
    let (base_url, _server) = spawn_server(test_state(Duration::seconds(300), grace)).await;
    let client = client_for(&base_url);

    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");

    let dead = dead_client().await;

    // First failure fixes the grace deadline. In Grace,
    // next_heartbeat_due is clamped to it — with a fresh 300s lease
    // the 80% mark is far out, so `due` IS the deadline.
    let err = dead
        .heartbeat(&mut session)
        .await
        .expect_err("heartbeat to a dead server must fail");
    assert!(matches!(err, ClientError::Transport(_)));
    assert!(session.is_alive());
    assert!(session.authorize().is_ok());
    let deadline = session.next_heartbeat_due(Utc::now()).unwrap();
    // Clamped to the deadline (~grace out), not the lease's 80% mark.
    assert!(deadline <= Utc::now() + grace);

    // A second failure inside the window must NOT re-arm the
    // deadline: once it passes, the very next heartbeat must report
    // GraceExhausted — if the second failure had moved the deadline,
    // the session would still be inside the window. If the first
    // call's latency already consumed the window, the second call
    // short-circuits to GraceExhausted — which itself proves the
    // deadline was fixed at the first failure.
    match dead.heartbeat(&mut session).await {
        // Transport means the deadline is still ahead — a second
        // failure inside the window must NOT have re-armed it, which
        // the post-deadline heartbeat below proves.
        Err(ClientError::Transport(_)) => assert!(session.is_alive()),
        Err(ClientError::GraceExhausted) => {
            assert!(!session.is_alive());
            return;
        }
        other => panic!("expected Transport or GraceExhausted, got {other:?}"),
    }

    // Once the deadline passes, the client itself calls it — the
    // server never gets a vote.
    let wait = (deadline - Utc::now()).to_std().unwrap_or_default()
        + std::time::Duration::from_millis(100);
    tokio::time::sleep(wait).await;
    let err = dead
        .heartbeat(&mut session)
        .await
        .expect_err("post-deadline heartbeat must fail");
    assert!(matches!(err, ClientError::GraceExhausted));
    assert!(!session.is_alive());
    assert!(matches!(
        session.authorize(),
        Err(ClientError::GraceExhausted)
    ));
}

/// writeup/ Diagram 2: the verifier mints the challenge. A stub
/// /exchange records the `challenge` the client sent and signs an
/// envelope echoing it; the client must accept the echo of its own
/// nonce, the nonce must be random, and two exchanges must never
/// share one.
#[tokio::test]
async fn client_mints_its_own_challenge() {
    let issuer = Arc::new(Issuer::from_seed(&ISSUER_SEED, KEY_ID));
    let seen = Arc::new(tokio::sync::Mutex::new(Vec::<[u8; 32]>::new()));
    let stub = {
        let issuer = issuer.clone();
        let seen = seen.clone();
        Router::new().route(
            "/exchange",
            post(move |Json(req): Json<Value>| {
                let issuer = issuer.clone();
                let seen = seen.clone();
                async move {
                    let challenge: [u8; 32] = req["challenge"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap() as u8)
                        .collect::<Vec<u8>>()
                        .try_into()
                        .unwrap();
                    seen.lock().await.push(challenge);
                    let session_id = Uuid::new_v4();
                    let now = Utc::now();
                    let lease = Lease {
                        session_id,
                        granted_at: now,
                        expires_at: now + Duration::seconds(300),
                        grace_period: Duration::seconds(60),
                    };
                    let body = serde_json::to_vec(&serde_json::json!({
                        "session_id": session_id,
                        "session_key": vec![0x11u8; 32],
                        "lease": lease,
                        "server_time": now,
                    }))
                    .unwrap();
                    let env = Envelope::issue(
                        &issuer,
                        IssueSpec {
                            challenge,
                            session_id,
                            audience: "keystone-client".into(),
                            operation: "session.exchange".into(),
                            issued_at: now,
                            expires_at: now + Duration::seconds(300),
                            body,
                        },
                    );
                    Json(serde_json::to_value(env).unwrap())
                }
            }),
        )
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, stub).await.unwrap();
    });
    let client = KeystoneClient::new_insecure(format!("http://{addr}"), issuers()).unwrap();

    // No /challenge route exists on the stub — the client must never
    // ask for one.
    client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("the echo of a client-minted nonce must verify");
    client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("second exchange");

    let seen = seen.lock().await;
    assert_eq!(seen.len(), 2, "each exchange posts exactly one challenge");
    assert_ne!(seen[0], [0u8; 32], "the nonce must be random, not zeroed");
    assert_ne!(seen[1], [0u8; 32], "the nonce must be random, not zeroed");
    assert_ne!(seen[0], seen[1], "two exchanges must never share a nonce");
}

/// The echo must be of THIS request's nonce: a stub that signs an
/// envelope for some other challenge is rejected as a mismatch, so a
/// captured exchange response can't be replayed under a fresh request.
#[tokio::test]
async fn exchange_rejects_echo_of_foreign_challenge() {
    async fn foreign_exchange() -> Json<Value> {
        let issuer = Issuer::from_seed(&ISSUER_SEED, KEY_ID);
        let session_id = Uuid::new_v4();
        let now = Utc::now();
        let lease = Lease {
            session_id,
            granted_at: now,
            expires_at: now + Duration::seconds(300),
            grace_period: Duration::seconds(60),
        };
        let body = serde_json::to_vec(&serde_json::json!({
            "session_id": session_id,
            "session_key": vec![0x11u8; 32],
            "lease": lease,
            "server_time": now,
        }))
        .unwrap();
        let env = Envelope::issue(
            &issuer,
            IssueSpec {
                challenge: [7u8; 32],
                session_id,
                audience: "keystone-client".into(),
                operation: "session.exchange".into(),
                issued_at: now,
                expires_at: now + Duration::seconds(300),
                body,
            },
        );
        Json(serde_json::to_value(env).unwrap())
    }
    let stub = Router::new().route("/exchange", post(foreign_exchange));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, stub).await.unwrap();
    });
    let client = KeystoneClient::new_insecure(format!("http://{addr}"), issuers()).unwrap();

    let err = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect_err("an envelope echoing a foreign nonce must be refused");
    assert!(
        matches!(err, ClientError::Core(KeystoneError::ChallengeMismatch)),
        "expected ChallengeMismatch, got {err:?}"
    );
}

#[tokio::test]
async fn drift_adjusted_time_rejects_stale_envelope() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");

    // A stub heartbeat that reports a server_time 120s ahead — the
    // session's drift estimate jumps forward — then answers the next
    // heartbeat with an envelope that expires between raw local time
    // and drift-adjusted time. Raw local time would accept it;
    // drift-adjusted time must reject it as Expired.
    let issuer = Arc::new(Issuer::from_seed(&ISSUER_SEED, KEY_ID));
    let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let stub = {
        let issuer = issuer.clone();
        let calls = calls.clone();
        Router::new().route(
            "/heartbeat",
            post(move |Json(req): Json<Value>| {
                let issuer = issuer.clone();
                let calls = calls.clone();
                async move {
                    let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let nonce: [u8; 32] = req["nonce"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap() as u8)
                        .collect::<Vec<u8>>()
                        .try_into()
                        .unwrap();
                    let session_id: Uuid = req["session_id"].as_str().unwrap().parse().unwrap();
                    let now = Utc::now();
                    let (server_time, expires_at) = if n == 0 {
                        // First call: claim the server clock is +120s.
                        (now + Duration::seconds(120), now + Duration::seconds(300))
                    } else {
                        // Second call: expires at local+60s — already
                        // dead on the drift-adjusted clock (+120s).
                        (now + Duration::seconds(120), now + Duration::seconds(60))
                    };
                    let lease = Lease {
                        session_id,
                        granted_at: now,
                        expires_at: now + Duration::seconds(300),
                        grace_period: Duration::seconds(60),
                    };
                    let body = serde_json::to_vec(&serde_json::json!({
                        "lease": lease,
                        "server_time": server_time,
                    }))
                    .unwrap();
                    let env = Envelope::issue(
                        &issuer,
                        IssueSpec {
                            challenge: nonce,
                            session_id,
                            audience: "keystone-client".into(),
                            operation: "session.heartbeat".into(),
                            issued_at: now,
                            expires_at,
                            body,
                        },
                    );
                    Json(serde_json::to_value(env).unwrap())
                }
            }),
        )
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, stub).await.unwrap();
    });
    let stub_client = KeystoneClient::new_insecure(format!("http://{addr}"), issuers()).unwrap();

    // First heartbeat installs the +120s drift.
    stub_client
        .heartbeat(&mut session)
        .await
        .expect("first heartbeat must succeed");
    assert!(session.clock_drift() > Duration::seconds(60));

    // Second heartbeat: the envelope is fresh by raw local time but
    // expired on the drift-adjusted clock — verification must fail.
    let err = stub_client
        .heartbeat(&mut session)
        .await
        .expect_err("stale envelope must fail on drift-adjusted time");
    assert!(matches!(err, ClientError::Core(KeystoneError::Expired)));
    // A verification failure is transient — the session survives.
    assert!(session.is_alive());
}

/// Every session-bound request stamps `issued_at` from the session's
/// drift-adjusted clock, not the raw local one: once a signed body has
/// reported the server +120s ahead, the next heartbeat's `issued_at`
/// must land ~120s ahead of local time — inside the server's skew
/// window even though the local clock alone would fall outside it.
#[tokio::test]
async fn session_requests_carry_drift_adjusted_issued_at() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");

    // Stub /heartbeat: records each request's `issued_at`, and always
    // reports a server clock 120s ahead of local.
    let issuer = Arc::new(Issuer::from_seed(&ISSUER_SEED, KEY_ID));
    let seen = Arc::new(tokio::sync::Mutex::new(Vec::<DateTime<Utc>>::new()));
    let stub = {
        let seen = seen.clone();
        Router::new().route(
            "/heartbeat",
            post(move |Json(req): Json<Value>| {
                let issuer = issuer.clone();
                let seen = seen.clone();
                async move {
                    let issued_at: DateTime<Utc> =
                        req["issued_at"].as_str().unwrap().parse().unwrap();
                    seen.lock().await.push(issued_at);
                    let nonce: [u8; 32] = req["nonce"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap() as u8)
                        .collect::<Vec<u8>>()
                        .try_into()
                        .unwrap();
                    let session_id: Uuid = req["session_id"].as_str().unwrap().parse().unwrap();
                    let now = Utc::now();
                    let lease = Lease {
                        session_id,
                        granted_at: now,
                        expires_at: now + Duration::seconds(300),
                        grace_period: Duration::seconds(60),
                    };
                    let body = serde_json::to_vec(&serde_json::json!({
                        "lease": lease,
                        "server_time": now + Duration::seconds(120),
                    }))
                    .unwrap();
                    let env = Envelope::issue(
                        &issuer,
                        IssueSpec {
                            challenge: nonce,
                            session_id,
                            audience: "keystone-client".into(),
                            operation: "session.heartbeat".into(),
                            issued_at: now,
                            expires_at: now + Duration::seconds(300),
                            body,
                        },
                    );
                    Json(serde_json::to_value(env).unwrap())
                }
            }),
        )
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, stub).await.unwrap();
    });
    let stub_client = KeystoneClient::new_insecure(format!("http://{addr}"), issuers()).unwrap();

    // First heartbeat: stamped before any drift is known — the real
    // exchange reported an honest clock — and installs the +120s.
    stub_client
        .heartbeat(&mut session)
        .await
        .expect("first heartbeat must succeed");
    assert!(session.clock_drift() > Duration::seconds(60));
    // Second heartbeat: the stamp must follow the drift.
    stub_client
        .heartbeat(&mut session)
        .await
        .expect("second heartbeat must succeed");

    let seen = seen.lock().await;
    let local = Utc::now();
    let first = seen[0] - local;
    let second = seen[1] - local;
    assert!(
        first.num_seconds().abs() < 5,
        "pre-drift issued_at must track local time, got {first}"
    );
    assert!(
        (second - Duration::seconds(120)).num_seconds().abs() < 5,
        "post-drift issued_at must sit ~120s ahead of local, got {second}"
    );
}

/// The client's replay cache: a stub that answers two heartbeats with
/// the SAME signed envelope must see the second accept fail
/// AlreadyConsumed — the envelope's own nonce is spent even though the
/// request that fetched it carried a fresh one.
#[tokio::test]
async fn replayed_heartbeat_envelope_is_consumed() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");

    // Stub /heartbeat: signs one envelope for the first request's
    // nonce, then replays that exact envelope for every later request.
    let issuer = Arc::new(Issuer::from_seed(&ISSUER_SEED, KEY_ID));
    let cached = Arc::new(tokio::sync::Mutex::new(None::<Envelope>));
    let stub = {
        let cached = cached.clone();
        Router::new().route(
            "/heartbeat",
            post(move |Json(req): Json<Value>| {
                let issuer = issuer.clone();
                let cached = cached.clone();
                async move {
                    let mut slot = cached.lock().await;
                    if let Some(env) = slot.clone() {
                        return Json(serde_json::to_value(env).unwrap());
                    }
                    let nonce: [u8; 32] = req["nonce"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap() as u8)
                        .collect::<Vec<u8>>()
                        .try_into()
                        .unwrap();
                    let session_id: Uuid = req["session_id"].as_str().unwrap().parse().unwrap();
                    let now = Utc::now();
                    let lease = Lease {
                        session_id,
                        granted_at: now,
                        expires_at: now + Duration::seconds(300),
                        grace_period: Duration::seconds(60),
                    };
                    let body = serde_json::to_vec(&serde_json::json!({
                        "lease": lease,
                        "server_time": now,
                    }))
                    .unwrap();
                    let env = Envelope::issue(
                        &issuer,
                        IssueSpec {
                            challenge: nonce,
                            session_id,
                            audience: "keystone-client".into(),
                            operation: "session.heartbeat".into(),
                            issued_at: now,
                            expires_at: now + Duration::seconds(300),
                            body,
                        },
                    );
                    *slot = Some(env.clone());
                    Json(serde_json::to_value(env).unwrap())
                }
            }),
        )
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, stub).await.unwrap();
    });
    let stub_client = KeystoneClient::new_insecure(format!("http://{addr}"), issuers()).unwrap();

    stub_client
        .heartbeat(&mut session)
        .await
        .expect("first heartbeat must succeed");
    let err = stub_client
        .heartbeat(&mut session)
        .await
        .expect_err("a replayed envelope must be rejected");
    assert!(
        matches!(err, ClientError::Core(KeystoneError::AlreadyConsumed)),
        "expected AlreadyConsumed, got {err:?}"
    );
    // Transient, not a verdict — the session survives.
    assert!(session.is_alive());
}

/// A 410 on heartbeat is a verdict, and the local state decides which:
/// Active → Expired, Grace → GraceExhausted. The distinction matters
/// because GraceExhausted is the client's own deadline catching up.
#[tokio::test]
async fn heartbeat_410_maps_expired_in_active_grace_exhausted_in_grace() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);

    // Stub /heartbeat that always answers 410.
    async fn gone() -> (axum::http::StatusCode, Json<Value>) {
        (
            axum::http::StatusCode::GONE,
            Json(serde_json::json!({ "error": "authorization expired" })),
        )
    }
    let stub = Router::new().route("/heartbeat", post(gone));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, stub).await.unwrap();
    });
    let gone_client = KeystoneClient::new_insecure(format!("http://{addr}"), issuers()).unwrap();

    // Active session + 410 → Dead(Expired).
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");
    let err = gone_client
        .heartbeat(&mut session)
        .await
        .expect_err("410 must reject");
    assert!(matches!(
        err,
        ClientError::ServerRejected { status: 410, .. }
    ));
    assert!(!session.is_alive());
    assert!(matches!(
        session.authorize(),
        Err(ClientError::Core(KeystoneError::Expired))
    ));

    // Grace session + 410 → Dead(GraceExhausted). Drive a session into
    // grace with a transport failure first.
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");
    let dead = dead_client().await;
    let _ = dead.heartbeat(&mut session).await; // transport → Grace
    assert!(session.is_alive());
    let err = gone_client
        .heartbeat(&mut session)
        .await
        .expect_err("410 in grace must reject");
    assert!(matches!(
        err,
        ClientError::ServerRejected { status: 410, .. }
    ));
    assert!(!session.is_alive());
    assert!(matches!(
        session.authorize(),
        Err(ClientError::GraceExhausted)
    ));
}

/// `stale_request` is the server saying "your clock is off", not a
/// verdict on the session: the client burns grace and keeps the
/// lease, same as any other transient code — a plain 401 would have
/// killed it.
#[tokio::test]
async fn stale_request_is_transient() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");

    async fn stale() -> (axum::http::StatusCode, Json<Value>) {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "request timestamp outside acceptable window",
                "code": "stale_request",
            })),
        )
    }
    let stub = Router::new().route("/heartbeat", post(stale));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, stub).await.unwrap();
    });
    let stale_client = KeystoneClient::new_insecure(format!("http://{addr}"), issuers()).unwrap();

    let failed_at = Utc::now();
    let err = stale_client
        .heartbeat(&mut session)
        .await
        .expect_err("stale_request must surface as a rejection");
    assert!(matches!(
        err,
        ClientError::ServerRejected { status: 401, .. }
    ));
    // Grace, not Dead: still alive, still authorizes, and the next
    // heartbeat is clamped to the grace deadline (60s) rather than
    // the Active 80%-of-lease mark (240s).
    assert!(session.is_alive());
    assert!(session.authorize().is_ok());
    let due = session
        .next_heartbeat_due(failed_at)
        .expect("grace session has a deadline");
    assert!(
        due <= failed_at + Duration::seconds(61),
        "expected grace clamp, got {due}"
    );
}

/// A stub /heartbeat that answers request `n` with a well-formed lease
/// envelope signed by `script[n]`'s issuer, announcing that entry's
/// `revoked_key_ids` in the body. The last entry repeats.
async fn spawn_scripted_heartbeat_stub(script: Vec<(Issuer, Vec<u8>)>) -> String {
    let script = Arc::new(script);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stub = Router::new().route(
        "/heartbeat",
        post(move |Json(req): Json<Value>| {
            let script = script.clone();
            let calls = calls.clone();
            async move {
                let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (issuer, revoked) = &script[n.min(script.len() - 1)];
                let nonce: [u8; 32] = req["nonce"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u8)
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap();
                let session_id: Uuid = req["session_id"].as_str().unwrap().parse().unwrap();
                let now = Utc::now();
                let lease = Lease {
                    session_id,
                    granted_at: now,
                    expires_at: now + Duration::seconds(300),
                    grace_period: Duration::seconds(60),
                };
                let body = serde_json::to_vec(&serde_json::json!({
                    "lease": lease,
                    "server_time": now,
                    "revoked_key_ids": revoked.as_slice(),
                }))
                .unwrap();
                let env = Envelope::issue(
                    issuer,
                    IssueSpec {
                        challenge: nonce,
                        session_id,
                        audience: "keystone-client".into(),
                        operation: "session.heartbeat".into(),
                        issued_at: now,
                        expires_at: now + Duration::seconds(300),
                        body,
                    },
                );
                Json(serde_json::to_value(env).unwrap())
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, stub).await.unwrap();
    });
    format!("http://{addr}")
}

const COMPROMISED_SEED: [u8; 32] = [0x77u8; 32];
const COMPROMISED_KEY_ID: u8 = 7;

/// A build trusting keys 1 and 7. Key 7 is the one about to leak.
fn two_key_issuers() -> TrustedIssuers {
    TrustedIssuers::new([
        (KEY_ID, pinned_key()),
        (
            COMPROMISED_KEY_ID,
            Issuer::from_seed(&COMPROMISED_SEED, COMPROMISED_KEY_ID).verifying_key(),
        ),
    ])
}

/// A lease body that verified under a still-trusted key carries the
/// server's revocation list, and the client applies it on acceptance:
/// key 7 is accepted before the announcement and refused after it.
#[tokio::test]
async fn client_applies_revoked_key_ids_from_lease_body() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let mut session = client_for(&base_url)
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange");

    // Call 0: signed by key 7, nothing revoked. Call 1: signed by key
    // 1, announces 7 revoked. Call 2 onward: signed by key 7 again.
    let compromised = || Issuer::from_seed(&COMPROMISED_SEED, COMPROMISED_KEY_ID);
    let stub_url = spawn_scripted_heartbeat_stub(vec![
        (compromised(), vec![]),
        (
            Issuer::from_seed(&ISSUER_SEED, KEY_ID),
            vec![COMPROMISED_KEY_ID],
        ),
        (compromised(), vec![]),
    ])
    .await;
    let client = KeystoneClient::new_insecure(&stub_url, two_key_issuers()).unwrap();
    assert_eq!(client.trusted_key_ids(), vec![KEY_ID, COMPROMISED_KEY_ID]);

    client
        .heartbeat(&mut session)
        .await
        .expect("key 7 is trusted until the server says otherwise");
    assert!(!client.is_issuer_revoked(COMPROMISED_KEY_ID));

    client
        .heartbeat(&mut session)
        .await
        .expect("the revoking lease body is itself signed by a trusted key");
    assert!(client.is_issuer_revoked(COMPROMISED_KEY_ID));
    assert_eq!(client.trusted_key_ids(), vec![KEY_ID]);

    let err = client
        .heartbeat(&mut session)
        .await
        .expect_err("an envelope from the revoked key must be refused");
    assert!(
        matches!(
            err,
            ClientError::Core(KeystoneError::UntrustedIssuer {
                key_id: COMPROMISED_KEY_ID
            })
        ),
        "expected UntrustedIssuer, got {err:?}"
    );
    // A refused envelope is a transient failure, not a verdict — the
    // lease already held keeps the session alive in grace.
    assert!(session.is_alive());
}

/// The real server signs with the compromised key; once the client
/// revokes it locally, every further envelope from that key is
/// refused even though the signature is still perfectly valid.
#[tokio::test]
async fn envelope_from_revoked_key_rejected_after_revocation() {
    let (base_url, _server) = spawn_server(test_state_with_issuer(
        Issuer::from_seed(&COMPROMISED_SEED, COMPROMISED_KEY_ID),
        Duration::seconds(300),
        Duration::seconds(60),
    ))
    .await;
    let client = KeystoneClient::new_insecure(&base_url, two_key_issuers()).unwrap();
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("key 7 is trusted before revocation");

    client.revoke_issuer_key(COMPROMISED_KEY_ID);

    let err = client
        .heartbeat(&mut session)
        .await
        .expect_err("heartbeat signed by a revoked key must fail");
    assert!(matches!(
        err,
        ClientError::Core(KeystoneError::UntrustedIssuer {
            key_id: COMPROMISED_KEY_ID
        })
    ));
    let err = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect_err("exchange signed by a revoked key must fail");
    assert!(matches!(
        err,
        ClientError::Core(KeystoneError::UntrustedIssuer {
            key_id: COMPROMISED_KEY_ID
        })
    ));
}

/// Two servers, two issuer keys, one build trusting both: the client
/// accepts either, and a build trusting only one refuses the other by
/// key id — without ever checking a signature.
#[tokio::test]
async fn multi_key_client_accepts_either_key() {
    let (url_key1, _server1) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let (url_key2, _server2) = spawn_server(test_state_with_issuer(
        Issuer::from_seed(&[8u8; 32], 2),
        Duration::seconds(300),
        Duration::seconds(60),
    ))
    .await;
    let both = TrustedIssuers::new([
        (KEY_ID, pinned_key()),
        (2, Issuer::from_seed(&[8u8; 32], 2).verifying_key()),
    ]);

    let client1 = KeystoneClient::new_insecure(&url_key1, both.clone()).unwrap();
    let mut s1 = client1
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange under key 1");
    client1
        .heartbeat(&mut s1)
        .await
        .expect("heartbeat under key 1");

    let client2 = KeystoneClient::new_insecure(&url_key2, both).unwrap();
    let mut s2 = client2
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange under key 2");
    client2
        .heartbeat(&mut s2)
        .await
        .expect("heartbeat under key 2");

    // Key 2 is unknown to a build that only baked key 1.
    let err = client_for(&url_key2)
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect_err("unknown key id must be refused");
    assert!(matches!(
        err,
        ClientError::Core(KeystoneError::UntrustedIssuer { key_id: 2 })
    ));
}

/// Revocation takes effect on the very next call, needs no restart or
/// server round-trip to be honored, and is shared by every clone of
/// the client — a loader and its helper threads see one trust set.
#[tokio::test]
async fn revoke_issuer_key_is_immediate() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let client = client_for(&base_url);
    let twin = client.clone();

    twin.revoke_issuer_key(KEY_ID);
    assert!(client.is_issuer_revoked(KEY_ID));
    assert!(client.trusted_key_ids().is_empty());

    let err = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect_err("no trusted key left — every envelope must be refused");
    assert!(matches!(
        err,
        ClientError::Core(KeystoneError::UntrustedIssuer { key_id: KEY_ID })
    ));
}
