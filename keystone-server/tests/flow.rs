//! End-to-end flow tests against the real router — exchange → attest
//! → heartbeat → revoke, plus every rejection the spec calls out.

use argon2::password_hash::PasswordHasher;
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration, Utc};
use http_body_util::BodyExt;
use keystone_core::{
    AccountFile, AccountGrant, AccountRecord, DeadReason, Entitlement, EntitlementSource, Envelope,
    Expectation, Issuer, Lease, REQUEST_SKEW, RequestBinding, SessionState, TrustedIssuers,
    mac_request,
};
use keystone_server::accounts::LocalAccounts;
use keystone_server::entitlement::StubEntitlementSource;
use keystone_server::state::{ArtifactHashes, RateLimiter, RateLimits};
use keystone_server::{AppState, SessionStore, build_router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;

const ACCOUNT: &str = "dev";
const SECRET: &str = "devpass";
const PRODUCT: &str = "dev-product";
const ADMIN_TOKEN: &str = "test-admin-token";

fn test_state() -> AppState {
    test_state_with(Duration::seconds(300), Utc::now() + Duration::days(30))
}

fn test_state_with(lease_ttl: Duration, entitlement_expiry: DateTime<Utc>) -> AppState {
    let entitlements = Arc::new(StubEntitlementSource::new(vec![
        (
            ACCOUNT.to_string(),
            SECRET.to_string(),
            vec![Entitlement {
                account: ACCOUNT.to_string(),
                product: PRODUCT.to_string(),
                expires_at: entitlement_expiry,
                features: vec!["all".to_string()],
            }],
        ),
        ("nogrant".to_string(), "nograntpass".to_string(), vec![]),
    ]));
    AppState {
        issuer: Arc::new(Issuer::from_seed(&[7u8; 32], 1)),
        store: SessionStore::new(),
        entitlements,
        admin_token_hash: Some(Sha256::digest(ADMIN_TOKEN.as_bytes()).into()),
        lease_ttl,
        grace_period: Duration::seconds(60),
        payload_dir: None,
        payload_secret: None,
        payload_epoch: 0,
        downloads: None,
        watermark_secret: None,
        rate_limits: RateLimits::default(),
        rate_limiter: Arc::new(RateLimiter::new()),
        artifact_hashes: Arc::new(ArtifactHashes::new()),
        revoked_key_ids: Arc::new(RwLock::new(BTreeSet::new())),
    }
}

/// The trust root a client of this server would bake in: exactly the
/// server's current key under its id.
fn issuers(state: &AppState) -> TrustedIssuers {
    TrustedIssuers::single(state.issuer.key_id(), state.issuer.verifying_key())
}

async fn post(app: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

fn arr32(v: &Value, key: &str) -> [u8; 32] {
    let a = v[key].as_array().expect("expected a 32-byte array field");
    assert_eq!(a.len(), 32);
    a.iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

/// Mint a client-side nonce — the verifier issues the challenge; the
/// server only ever echoes it.
fn fresh_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    nonce
}

/// A heartbeat body stamped `issued_at` and MAC'd over it — the shape
/// the client sends. Tests that probe the window pass a shifted stamp.
fn heartbeat_body(session: &Session, nonce: [u8; 32], issued_at: DateTime<Utc>) -> Value {
    let mac = mac_request(
        &session.key,
        &RequestBinding {
            session_id: &session.id,
            nonce: &nonce,
            issued_at,
            context: b"heartbeat",
        },
    );
    json!({ "session_id": session.id, "nonce": nonce, "issued_at": issued_at, "mac": mac })
}

/// An attest body stamped `issued_at` and MAC'd over it.
fn attest_body(session: &Session, nonce: [u8; 32], issued_at: DateTime<Utc>) -> Value {
    let mac = mac_request(
        &session.key,
        &RequestBinding {
            session_id: &session.id,
            nonce: &nonce,
            issued_at,
            context: b"attest",
        },
    );
    json!({
        "session_id": session.id,
        "challenge": nonce,
        "issued_at": issued_at,
        "process_id": "dev-app.exe",
        "mac": mac,
    })
}

struct Session {
    id: Uuid,
    key: [u8; 32],
}

/// Run exchange with a fresh nonce; asserts the exchange envelope verifies.
async fn establish_session(app: &axum::Router, state: &AppState) -> Session {
    establish_session_as(app, state, ACCOUNT, SECRET, PRODUCT).await
}

/// Exchange for an arbitrary account/product — for tests that drive a
/// file-backed entitlement source.
async fn establish_session_as(
    app: &axum::Router,
    state: &AppState,
    account: &str,
    secret: &str,
    product: &str,
) -> Session {
    let nonce = fresh_nonce();
    let hwid = [9u8; 32];
    let (status, body) = post(
        app,
        "/exchange",
        json!({
            "account": account,
            "secret": secret,
            "product": product,
            "hwid": hwid,
            "challenge": nonce,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "exchange failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();

    let body_json: Value = serde_json::from_slice(&env.body).unwrap();
    let session_id: Uuid = serde_json::from_value(body_json["session_id"].clone()).unwrap();
    env.verify(
        &issuers(state),
        &Expectation {
            challenge: &nonce,
            session_id: &session_id,
            audience: "keystone-client",
            operation: "session.exchange",
            now: Utc::now(),
        },
    )
    .expect("exchange envelope must verify");

    Session {
        id: session_id,
        key: arr32(&body_json, "session_key"),
    }
}

/// Attest with a fresh client nonce and a valid MAC.
async fn attest_ok(app: &axum::Router, state: &AppState, session: &Session) -> (Envelope, Lease) {
    let nonce = fresh_nonce();
    let (status, body) = post(app, "/attest", attest_body(session, nonce, Utc::now())).await;
    assert_eq!(status, StatusCode::OK, "attest failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    env.verify(
        &issuers(state),
        &Expectation {
            challenge: &nonce,
            session_id: &session.id,
            audience: "keystone-app",
            operation: "session.attest",
            now: Utc::now(),
        },
    )
    .expect("attest envelope must verify");
    let attest_body: Value = serde_json::from_slice(&env.body).unwrap();
    let lease: Lease = serde_json::from_value(attest_body["lease"].clone()).unwrap();
    // The signed envelope never outlives the lease it carries.
    assert_eq!(env.expires_at, lease.expires_at);
    (env, lease)
}

#[tokio::test]
async fn happy_path_full_flow() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let (_, lease) = attest_ok(&app, &state, &session).await;
    assert_eq!(lease.session_id, session.id);

    // Heartbeat: MAC over session_id + nonce + issued_at proves
    // session-key possession; the response is a signed lease renewal.
    let hb_nonce = [22u8; 32];
    let (status, body) = post(
        &app,
        "/heartbeat",
        heartbeat_body(&session, hb_nonce, Utc::now()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "heartbeat failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    env.verify(
        &issuers(&state),
        &Expectation {
            challenge: &hb_nonce,
            session_id: &session.id,
            audience: "keystone-client",
            operation: "session.heartbeat",
            now: Utc::now(),
        },
    )
    .expect("heartbeat envelope must verify");
    let hb_body: Value = serde_json::from_slice(&env.body).unwrap();
    let renewed: Lease = serde_json::from_value(hb_body["lease"].clone()).unwrap();
    assert!(renewed.expires_at > lease.granted_at);
    assert_eq!(env.expires_at, renewed.expires_at);

    // Revoke: explicit death, admin-gated.
    let (status, _) = post(
        &app,
        "/revoke",
        json!({ "session_id": session.id, "admin_token": ADMIN_TOKEN }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn bad_credentials_rejected() {
    let state = test_state();
    let app = build_router(state);
    let nonce = fresh_nonce();
    let hwid = [9u8; 32];
    let (status, body) = post(
        &app,
        "/exchange",
        json!({
            "account": ACCOUNT,
            "secret": "wrong",
            "product": PRODUCT,
            "hwid": hwid,
            "challenge": nonce,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn wrong_product_rejected() {
    let state = test_state();
    let app = build_router(state);
    let nonce = fresh_nonce();
    let hwid = [9u8; 32];
    let (status, _) = post(
        &app,
        "/exchange",
        json!({
            "account": ACCOUNT,
            "secret": SECRET,
            "product": "other-product",
            "hwid": hwid,
            "challenge": nonce,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn zero_grant_account_authenticates_then_forbidden() {
    let state = test_state();
    let app = build_router(state);
    let nonce = fresh_nonce();
    let hwid = [9u8; 32];
    // Valid credentials, no grants at all → 403 at the entitlement
    // check, not 401 at authentication.
    let (status, _) = post(
        &app,
        "/exchange",
        json!({
            "account": "nogrant",
            "secret": "nograntpass",
            "product": PRODUCT,
            "hwid": hwid,
            "challenge": nonce,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn heartbeat_wrong_mac_rejected() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let nonce = [33u8; 32];
    let bad_mac = [0xAAu8; 32];
    let (status, _) = post(
        &app,
        "/heartbeat",
        json!({ "session_id": session.id, "nonce": nonce, "issued_at": Utc::now(), "mac": bad_mac }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn heartbeat_after_revoke_stays_dead() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let (status, _) = post(
        &app,
        "/revoke",
        json!({ "session_id": session.id, "admin_token": ADMIN_TOKEN }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // A correctly-MAC'd heartbeat must still fail — revocation is
    // checked before the MAC so nothing resurrects a dead session.
    let nonce = [44u8; 32];
    let (status, _) = post(
        &app,
        "/heartbeat",
        heartbeat_body(&session, nonce, Utc::now()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // And the record is still dead.
    let view = state.store.get(&session.id).unwrap();
    assert!(matches!(
        view.state,
        keystone_core::SessionState::Dead {
            reason: keystone_core::DeadReason::Revoked
        }
    ));
}

#[tokio::test]
async fn heartbeat_after_lease_expiry_kills_session() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    // Force the lease into the past — an Active session whose lease
    // lapsed must die on the next heartbeat, not renew.
    state.store.with_mut(&session.id, |rec| {
        if let keystone_core::SessionState::Active { lease } = &mut rec.state {
            lease.expires_at = Utc::now() - Duration::seconds(1);
        }
    });

    let nonce = [55u8; 32];
    let (status, _) = post(
        &app,
        "/heartbeat",
        heartbeat_body(&session, nonce, Utc::now()),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
    let view = state.store.get(&session.id).unwrap();
    assert!(matches!(
        view.state,
        keystone_core::SessionState::Dead {
            reason: keystone_core::DeadReason::Expired
        }
    ));
}

#[tokio::test]
async fn heartbeat_after_entitlement_expiry_kills_session() {
    // The grant lapses on its own clock — the live re-resolution on
    // heartbeat must kill the session rather than renew it.
    // Two seconds of grant: enough headroom that the argon2 verify
    // inside establish_session can't outlast it under CPU contention
    // (a 500ms window flaked when 8 test binaries ran in parallel).
    let grant_expiry = Utc::now() + Duration::seconds(2);
    let state = test_state_with(Duration::seconds(300), grant_expiry);
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    // Sleep only as long as it actually takes to cross the expiry, plus
    // a margin — no fixed 600ms that assumes the exchange was fast.
    let remaining = (grant_expiry - Utc::now()).num_milliseconds().max(0) as u64 + 100;
    tokio::time::sleep(std::time::Duration::from_millis(remaining)).await;

    let nonce = [66u8; 32];
    let (status, _) = post(
        &app,
        "/heartbeat",
        heartbeat_body(&session, nonce, Utc::now()),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
    let view = state.store.get(&session.id).unwrap();
    assert!(matches!(
        view.state,
        keystone_core::SessionState::Dead {
            reason: keystone_core::DeadReason::Expired
        }
    ));
}

#[tokio::test]
async fn attest_requires_mac() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    // Missing MAC → 401, not a parse error.
    let nonce = fresh_nonce();
    let (status, _) = post(
        &app,
        "/attest",
        json!({
            "session_id": session.id,
            "challenge": nonce,
            "issued_at": Utc::now(),
            "process_id": "dev-app.exe",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Wrong MAC → 401.
    let nonce = fresh_nonce();
    let bad_mac = [0xBBu8; 32];
    let (status, _) = post(
        &app,
        "/attest",
        json!({
            "session_id": session.id,
            "challenge": nonce,
            "issued_at": Utc::now(),
            "process_id": "dev-app.exe",
            "mac": bad_mac,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_requires_admin_token() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    // No token → 403.
    let (status, _) = post(&app, "/revoke", json!({ "session_id": session.id })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Wrong token → 403.
    let (status, _) = post(
        &app,
        "/revoke",
        json!({ "session_id": session.id, "admin_token": "nope" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Session is still alive — a failed revoke must not kill it.
    let view = state.store.get(&session.id).unwrap();
    assert!(matches!(
        view.state,
        keystone_core::SessionState::Active { .. }
    ));
}

#[tokio::test]
async fn revoke_disabled_without_admin_token() {
    let mut state = test_state();
    state.admin_token_hash = None;
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let (status, _) = post(
        &app,
        "/revoke",
        json!({ "session_id": session.id, "admin_token": ADMIN_TOKEN }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unknown_session_attest_and_heartbeat() {
    let state = test_state();
    let app = build_router(state.clone());

    // Attest against a session that doesn't exist → 404 (challenge is
    // valid; the session lookup is what fails).
    let nonce = fresh_nonce();
    let mac = [0xCCu8; 32];
    let (status, _) = post(
        &app,
        "/attest",
        json!({
            "session_id": Uuid::new_v4(),
            "challenge": nonce,
            "issued_at": Utc::now(),
            "process_id": "dev-app.exe",
            "mac": mac,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let hb_nonce = [77u8; 32];
    let (status, _) = post(
        &app,
        "/heartbeat",
        json!({ "session_id": Uuid::new_v4(), "nonce": hb_nonce, "issued_at": Utc::now(), "mac": mac }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dev_seed_disabled_yields_no_backend() {
    // Without KEYSTONE_DEV_SEED the stub seeds nothing — main() treats
    // None as fatal. Asserted at the seam so tests stay env-free.
    assert!(keystone_server::entitlement::dev_seed_source(false).is_none());
    assert!(keystone_server::entitlement::dev_seed_source(true).is_some());
}

/// A file-backed state: LocalAccounts over a temp accounts.json so
/// tests can rewrite grants mid-session.
fn file_backed_state(path: &std::path::Path) -> AppState {
    let mut state = test_state();
    state.entitlements = Arc::new(LocalAccounts::open(path.to_path_buf()));
    state
}

fn write_accounts_file(dir: &std::path::Path, file: &AccountFile) -> std::path::PathBuf {
    let path = dir.join("accounts.json");
    file.save(&path).unwrap();
    path
}

fn file_record(name: &str, secret: &str, grants: Vec<AccountGrant>) -> AccountRecord {
    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    AccountRecord {
        name: name.to_string(),
        secret_hash: argon2::Argon2::default()
            .hash_password(secret.as_bytes(), &salt)
            .unwrap()
            .to_string(),
        entitlements: grants,
        cert_sha256: None,
    }
}

fn file_grant(product: &str, expires_at: DateTime<Utc>) -> AccountGrant {
    AccountGrant {
        product: product.to_string(),
        expires_at,
        features: vec!["all".to_string()],
    }
}

/// Rewrite the accounts file and bump its mtime so the backend's
/// mtime-keyed reload can't miss the change on a coarse filesystem.
fn rewrite_accounts(path: &std::path::Path, file: &AccountFile) {
    file.save(path).unwrap();
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
        .unwrap();
}

async fn heartbeat_once(
    app: &axum::Router,
    session: &Session,
    nonce: [u8; 32],
) -> (StatusCode, Value) {
    post(
        app,
        "/heartbeat",
        heartbeat_body(session, nonce, Utc::now()),
    )
    .await
}

/// The blocker this wave fixes: pulling the grant from the accounts
/// file must kill the session on its next heartbeat — not when the
/// recorded expiry passes.
#[tokio::test]
async fn heartbeat_after_grant_revoked_kills_session() {
    let dir = std::env::temp_dir().join(format!("keystone-flow-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = write_accounts_file(
        &dir,
        &AccountFile {
            accounts: vec![file_record(
                ACCOUNT,
                SECRET,
                vec![file_grant(PRODUCT, Utc::now() + Duration::days(30))],
            )],
        },
    );
    let state = file_backed_state(&path);
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    // Pull the grant mid-session — the file backend reloads on mtime.
    rewrite_accounts(
        &path,
        &AccountFile {
            accounts: vec![file_record(ACCOUNT, SECRET, vec![])],
        },
    );

    let (status, _) = heartbeat_once(&app, &session, [0x91u8; 32]).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "pulled grant must kill: {status}"
    );
    let view = state.store.get(&session.id).unwrap();
    assert!(matches!(
        view.state,
        keystone_core::SessionState::Dead {
            reason: keystone_core::DeadReason::Revoked
        }
    ));
}

/// The same live re-resolution lets a grant EXTENSION propagate: the
/// renewed lease is capped by the new expiry, not the old one.
#[tokio::test]
async fn heartbeat_after_grant_extended_uses_new_expiry() {
    let dir = std::env::temp_dir().join(format!("keystone-flow-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = write_accounts_file(
        &dir,
        &AccountFile {
            accounts: vec![file_record(
                ACCOUNT,
                SECRET,
                vec![file_grant(PRODUCT, Utc::now() + Duration::seconds(120))],
            )],
        },
    );
    let state = file_backed_state(&path);
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let extended = Utc::now() + Duration::days(30);
    rewrite_accounts(
        &path,
        &AccountFile {
            accounts: vec![file_record(
                ACCOUNT,
                SECRET,
                vec![file_grant(PRODUCT, extended)],
            )],
        },
    );

    let (status, body) = heartbeat_once(&app, &session, [0x92u8; 32]).await;
    assert_eq!(status, StatusCode::OK, "heartbeat failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    let hb_body: Value = serde_json::from_slice(&env.body).unwrap();
    let renewed: Lease = serde_json::from_value(hb_body["lease"].clone()).unwrap();
    // lease_ttl is 300s; the old grant would have capped the renewal
    // at ~120s out. The extension must lift the cap.
    assert!(
        renewed.expires_at > Utc::now() + Duration::seconds(200),
        "renewed lease must reflect the extended grant"
    );
}

/// /revoke's account form kills every live session for that account.
#[tokio::test]
async fn revoke_by_account_kills_all_sessions() {
    let state = test_state();
    let app = build_router(state.clone());
    let s1 = establish_session(&app, &state).await;
    let s2 = establish_session(&app, &state).await;

    let (status, body) = post(
        &app,
        "/revoke",
        json!({ "account": ACCOUNT, "admin_token": ADMIN_TOKEN }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], 2);

    for s in [&s1, &s2] {
        let view = state.store.get(&s.id).unwrap();
        assert!(matches!(
            view.state,
            keystone_core::SessionState::Dead {
                reason: keystone_core::DeadReason::Revoked
            }
        ));
        let (status, _) = heartbeat_once(&app, s, [0x93u8; 32]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // Both fields at once, and neither, are malformed.
    let (status, _) = post(
        &app,
        "/revoke",
        json!({ "session_id": s1.id, "account": ACCOUNT, "admin_token": ADMIN_TOKEN }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(&app, "/revoke", json!({ "admin_token": ADMIN_TOKEN })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// N parallel heartbeats on one session with the same nonce: exactly
/// one consume wins, the rest are 409 — no double-spend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_heartbeats_single_consume() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let nonce = [0xA5u8; 32];
    let body = heartbeat_body(&session, nonce, Utc::now());
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let app = app.clone();
        let body = body.clone();
        set.spawn(async move { post(&app, "/heartbeat", body).await.0 });
    }
    let mut ok = 0;
    let mut conflict = 0;
    while let Some(status) = set.join_next().await {
        match status.unwrap() {
            StatusCode::OK => ok += 1,
            StatusCode::CONFLICT => conflict += 1,
            other => panic!("unexpected heartbeat status {other}"),
        }
    }
    assert_eq!(ok, 1, "exactly one heartbeat may consume the nonce");
    assert_eq!(conflict, 7);
}

/// Attest is replay-protected the same way heartbeat is: the app's
/// nonce is remembered in the session's consumed set, so the identical
/// request — same nonce, same valid MAC — is a 409 the second time.
#[tokio::test]
async fn attest_replayed_nonce_rejected() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let req = attest_body(&session, fresh_nonce(), Utc::now());
    let (status, _) = post(&app, "/attest", req.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post(&app, "/attest", req).await;
    assert_eq!(status, StatusCode::CONFLICT, "replayed attest: {body}");

    // A replay is not a verdict — the session stays live.
    let view = state.store.get(&session.id).unwrap();
    assert!(matches!(view.state, SessionState::Active { .. }));
}

/// The consumed set outlives the lease window: a heartbeat renews the
/// lease, and a captured attest nonce must still be dead afterwards.
#[tokio::test]
async fn attest_nonce_survives_lease_renewal() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let req = attest_body(&session, fresh_nonce(), Utc::now());
    let (status, _) = post(&app, "/attest", req.clone()).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = heartbeat_once(&app, &session, fresh_nonce()).await;
    assert_eq!(status, StatusCode::OK, "heartbeat failed: {body}");

    let (status, body) = post(&app, "/attest", req).await;
    assert_eq!(status, StatusCode::CONFLICT, "attest after renewal: {body}");
}

/// A heartbeat stamped outside `now ± REQUEST_SKEW` is refused before
/// the MAC is even checked — and as a transient `stale_request`, not
/// a verdict: an honest skewed clock self-corrects, so the session
/// must stay live.
#[tokio::test]
async fn stale_heartbeat_rejected_as_transient() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let stale = Utc::now() - Duration::minutes(6);
    let (status, body) = post(
        &app,
        "/heartbeat",
        heartbeat_body(&session, [1u8; 32], stale),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "stale heartbeat: {body}");
    assert_eq!(body["code"], "stale_request");

    let view = state.store.get(&session.id).unwrap();
    assert!(matches!(view.state, SessionState::Active { .. }));
}

/// The window is symmetric: a future-dated request is as suspicious as
/// a stale one and gets the same transient denial.
#[tokio::test]
async fn future_dated_heartbeat_rejected() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let future = Utc::now() + Duration::minutes(6);
    let (status, body) = post(
        &app,
        "/heartbeat",
        heartbeat_body(&session, [2u8; 32], future),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "future heartbeat: {body}");
    assert_eq!(body["code"], "stale_request");

    let view = state.store.get(&session.id).unwrap();
    assert!(matches!(view.state, SessionState::Active { .. }));
}

/// `issued_at` is inside the MAC: a captured request can't be kept
/// alive by rewriting its timestamp into the window.
#[tokio::test]
async fn tampered_issued_at_fails_mac() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let minted_at = Utc::now();
    let mut req = heartbeat_body(&session, [3u8; 32], minted_at);
    req["issued_at"] = json!(minted_at + Duration::seconds(1));
    let (status, body) = post(&app, "/heartbeat", req).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "tampered issued_at: {body}"
    );
    assert_eq!(body["error"], "response MAC does not match");
}

/// What bounds the consumed set: a nonce is remembered until
/// `issued_at + REQUEST_SKEW` — the moment the timestamp alone would
/// reject a replay — not until the grant expires. A heartbeat minted
/// just inside the window therefore leaves an entry that lapses in
/// about a second, on a session whose grant runs for 30 days.
#[tokio::test]
async fn consumed_nonce_expires_with_freshness_window() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let nonce = [4u8; 32];
    let issued_at = Utc::now() - REQUEST_SKEW + Duration::seconds(1);
    let (status, body) = post(
        &app,
        "/heartbeat",
        heartbeat_body(&session, nonce, issued_at),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "edge-of-window heartbeat: {body}");

    let expiry = issued_at + REQUEST_SKEW;
    state
        .store
        .with_mut(&session.id, |rec| {
            assert!(rec.consumed.is_consumed(&nonce));
            rec.consumed
                .evict_expired(expiry - Duration::milliseconds(1));
            assert!(
                rec.consumed.is_consumed(&nonce),
                "nonce must survive to the window edge"
            );
            rec.consumed.evict_expired(expiry);
            assert!(
                !rec.consumed.is_consumed(&nonce),
                "nonce must not outlive the window"
            );
        })
        .expect("session must exist");
}

/// The nonce is the client's own: whatever it sends is what the signed
/// envelope echoes — the server validates nothing about it.
#[tokio::test]
async fn exchange_echoes_client_challenge() {
    let state = test_state();
    let app = build_router(state.clone());
    let nonce = fresh_nonce();
    let hwid = [9u8; 32];
    let (status, body) = post(
        &app,
        "/exchange",
        json!({
            "account": ACCOUNT,
            "secret": SECRET,
            "product": PRODUCT,
            "hwid": hwid,
            "challenge": nonce,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "exchange failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    assert_eq!(env.challenge, nonce);
}

/// Sessions are in-memory by design (README §Layout): a
/// restarted server has no record of the session, so the old one
/// sees 404 and must re-exchange — and the re-exchange must work
/// without any state carried across the restart.
#[tokio::test]
async fn restart_recovery_reexchange_succeeds() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    // "Restart": a fresh store behind a fresh router — the session
    // record is gone.
    let restarted_state = test_state();
    let restarted = build_router(restarted_state.clone());
    let (status, _) = heartbeat_once(&restarted, &session, [0xB1u8; 32]).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "restarted server must 404");

    // Re-exchange against the restarted server: a new session, and a
    // heartbeat on it renews normally.
    let fresh = establish_session(&restarted, &restarted_state).await;
    assert_ne!(fresh.id, session.id);
    let (status, body) = heartbeat_once(&restarted, &fresh, [0xB2u8; 32]).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "post-restart heartbeat failed: {body}"
    );
}

/// A Grace record on the server means the store was seeded from
/// outside — the server only ever creates Active or Dead. Attest AND
/// heartbeat must both deny it as 403 session_not_active, even with a
/// valid MAC.
#[tokio::test]
async fn grace_record_denied_on_attest_and_heartbeat() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    state
        .store
        .with_mut(&session.id, |rec| {
            if let keystone_core::SessionState::Active { lease } = &rec.state {
                rec.state = keystone_core::SessionState::Grace {
                    lease: lease.clone(),
                    deadline: Utc::now() + Duration::seconds(30),
                };
            }
        })
        .expect("session must exist");

    // Attest: valid challenge, valid MAC — still 403 session_not_active.
    let (status, body) = post(
        &app,
        "/attest",
        attest_body(&session, fresh_nonce(), Utc::now()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "session_not_active");

    // Heartbeat: valid MAC — same denial.
    let hb_nonce = [0x44u8; 32];
    let (status, body) = post(
        &app,
        "/heartbeat",
        heartbeat_body(&session, hb_nonce, Utc::now()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "session_not_active");
}

/// Exchange has two sliding-window limits: per-IP and per-account.
/// Both must answer 429 rate_limited past the cap.
#[tokio::test]
async fn exchange_rate_limited_per_ip_and_account() {
    // Per-IP: in-process requests share the "unknown" bucket.
    let mut state = test_state();
    state.rate_limits.exchange_per_ip = 2;
    let app = build_router(state);
    let hwid = [9u8; 32];
    for _ in 0..2 {
        let nonce = fresh_nonce();
        let (status, _) = post(
            &app,
            "/exchange",
            json!({
                "account": ACCOUNT, "secret": "wrong", "product": PRODUCT,
                "hwid": hwid, "challenge": nonce,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = post(
        &app,
        "/exchange",
        json!({
            "account": ACCOUNT, "secret": SECRET, "product": PRODUCT,
            "hwid": hwid, "challenge": vec![0u8; 32],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");

    // Per-account: a high IP cap isolates the account bucket.
    let mut state = test_state();
    state.rate_limits.exchange_per_ip = 100;
    state.rate_limits.exchange_per_account = 2;
    let app = build_router(state);
    for _ in 0..2 {
        let nonce = fresh_nonce();
        let (status, _) = post(
            &app,
            "/exchange",
            json!({
                "account": ACCOUNT, "secret": "wrong", "product": PRODUCT,
                "hwid": hwid, "challenge": nonce,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = post(
        &app,
        "/exchange",
        json!({
            "account": ACCOUNT, "secret": SECRET, "product": PRODUCT,
            "hwid": hwid, "challenge": vec![0u8; 32],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
}

/// /revoke's per-IP limit fires before the admin-token check — a
/// token-guessing flood must not be free.
#[tokio::test]
async fn revoke_rate_limited_after_burst() {
    let mut state = test_state();
    state.rate_limits.revoke_per_ip = 2;
    let app = build_router(state);

    for _ in 0..2 {
        let (status, _) = post(
            &app,
            "/revoke",
            json!({ "session_id": Uuid::new_v4(), "admin_token": "guessed" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, body) = post(
        &app,
        "/revoke",
        json!({ "session_id": Uuid::new_v4(), "admin_token": ADMIN_TOKEN }),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
}

/// HWID anomaly is a signal, not a gate (README: assume spoofable):
/// a second exchange for the same account with a different fingerprint
/// inside the window must still return 200.
#[tokio::test]
async fn hwid_anomaly_does_not_gate_exchange() {
    let state = test_state();
    let app = build_router(state.clone());
    let _s1 = establish_session(&app, &state).await; // hwid [9;32]

    let nonce = fresh_nonce();
    let (status, body) = post(
        &app,
        "/exchange",
        json!({
            "account": ACCOUNT,
            "secret": SECRET,
            "product": PRODUCT,
            "hwid": vec![0x77u8; 32], // different fingerprint, same account
            "challenge": nonce,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "anomalous fingerprint must not block exchange: {body}"
    );
}

/// A heartbeat MAC minted for session A must not verify against
/// session B — the session_id is inside the tag.
#[tokio::test]
async fn heartbeat_mac_replay_across_sessions_rejected() {
    let state = test_state();
    let app = build_router(state.clone());
    let a = establish_session(&app, &state).await;
    let b = establish_session(&app, &state).await;

    let nonce = [0x66u8; 32];
    let issued_at = Utc::now();
    let mac_for_a = mac_request(
        &a.key,
        &RequestBinding {
            session_id: &a.id,
            nonce: &nonce,
            issued_at,
            context: b"heartbeat",
        },
    );
    let (status, _) = post(
        &app,
        "/heartbeat",
        json!({ "session_id": b.id, "nonce": nonce, "issued_at": issued_at, "mac": mac_for_a }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // B is untouched — a foreign MAC is not a verdict on the session.
    let view = state.store.get(&b.id).unwrap();
    assert!(matches!(
        view.state,
        keystone_core::SessionState::Active { .. }
    ));
}

/// The stub honours the same contract as `LocalAccounts`: an expired
/// grant reads as no grant. Exchange therefore denies it the way it
/// denies any missing entitlement — 403, never a session.
#[tokio::test]
async fn stub_entitlement_filters_expired_grants() {
    let stub = StubEntitlementSource::new(vec![(
        ACCOUNT.to_string(),
        SECRET.to_string(),
        vec![Entitlement {
            account: ACCOUNT.to_string(),
            product: PRODUCT.to_string(),
            expires_at: Utc::now() - Duration::seconds(1),
            features: vec!["all".to_string()],
        }],
    )]);
    assert!(stub.entitlement(ACCOUNT, PRODUCT).await.unwrap().is_none());

    let state = test_state_with(Duration::seconds(300), Utc::now() - Duration::seconds(1));
    let app = build_router(state);
    let nonce = fresh_nonce();
    let (status, body) = post(
        &app,
        "/exchange",
        json!({
            "account": ACCOUNT,
            "secret": SECRET,
            "product": PRODUCT,
            "hwid": vec![9u8; 32],
            "challenge": nonce,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// README key compromise: revoking an issuer key kills every live
/// session and records the id so clients hear about it.
#[tokio::test]
async fn revoke_key_id_kills_all_sessions() {
    let state = test_state();
    let app = build_router(state.clone());
    let s1 = establish_session(&app, &state).await;
    let s2 = establish_session(&app, &state).await;

    let (status, body) = post(
        &app,
        "/revoke",
        json!({ "key_id": 1, "admin_token": ADMIN_TOKEN }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked"], 2);
    assert_eq!(body["key_id"], 1);
    assert_eq!(state.revoked_key_ids_snapshot(), vec![1]);

    for s in [&s1, &s2] {
        let view = state.store.get(&s.id).unwrap();
        assert!(matches!(
            view.state,
            SessionState::Dead {
                reason: DeadReason::Revoked
            }
        ));
        let (status, _) = heartbeat_once(&app, s, [0x94u8; 32]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    // key_id is exclusive with the other two forms.
    let (status, _) = post(
        &app,
        "/revoke",
        json!({ "session_id": s1.id, "key_id": 1, "admin_token": ADMIN_TOKEN }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // And still admin-gated.
    let (status, _) = post(&app, "/revoke", json!({ "key_id": 2 })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Every grant body — exchange, attest, heartbeat — carries the
/// revoked issuer ids so a client learns about a compromised key on
/// its very next round trip.
#[tokio::test]
async fn lease_body_carries_revoked_key_ids() {
    let state = test_state();
    state.revoked_key_ids.write().unwrap().extend([7u8, 3u8]);
    let app = build_router(state.clone());

    let nonce = fresh_nonce();
    let (status, body) = post(
        &app,
        "/exchange",
        json!({
            "account": ACCOUNT,
            "secret": SECRET,
            "product": PRODUCT,
            "hwid": vec![9u8; 32],
            "challenge": nonce,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    let exchange_body: Value = serde_json::from_slice(&env.body).unwrap();
    assert_eq!(exchange_body["revoked_key_ids"], json!([3, 7]));
    let session = Session {
        id: serde_json::from_value(exchange_body["session_id"].clone()).unwrap(),
        key: arr32(&exchange_body, "session_key"),
    };

    let (env, _) = attest_ok(&app, &state, &session).await;
    let attest_body: Value = serde_json::from_slice(&env.body).unwrap();
    assert_eq!(attest_body["revoked_key_ids"], json!([3, 7]));

    let (status, body) = heartbeat_once(&app, &session, [0x95u8; 32]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    let hb_body: Value = serde_json::from_slice(&env.body).unwrap();
    assert_eq!(hb_body["revoked_key_ids"], json!([3, 7]));
}

/// Past the per-session window /heartbeat answers 429 rate_limited —
/// transient, and the session itself stays alive.
#[tokio::test]
async fn heartbeat_rate_limited() {
    let mut state = test_state();
    state.rate_limits.heartbeat_per_session = 2;
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    for nonce in [[0xA1u8; 32], [0xA2u8; 32]] {
        let (status, body) = heartbeat_once(&app, &session, nonce).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = heartbeat_once(&app, &session, [0xA3u8; 32]).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
    assert!(matches!(
        state.store.get(&session.id).unwrap().state,
        SessionState::Active { .. }
    ));

    // Buckets are per session: a second session is untouched.
    let other = establish_session(&app, &state).await;
    let (status, body) = heartbeat_once(&app, &other, [0xA4u8; 32]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Same for /attest — and the limit fires before the nonce is
/// consumed, so a throttled attest can retry with the same nonce.
#[tokio::test]
async fn attest_rate_limited() {
    let mut state = test_state();
    state.rate_limits.attest_per_session = 2;
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    attest_ok(&app, &state, &session).await;
    attest_ok(&app, &state, &session).await;
    let (status, body) = post(
        &app,
        "/attest",
        attest_body(&session, fresh_nonce(), Utc::now()),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
}

/// Client-supplied identifiers are sanitized before they reach a log
/// line: only `[A-Za-z0-9._-]` survives, capped at 64 chars.
#[test]
fn sanitize_for_log_strips_and_truncates() {
    use keystone_server::routes::sanitize_for_log;
    assert_eq!(sanitize_for_log("dev-app.exe"), "dev-app.exe");
    assert_eq!(
        sanitize_for_log("evil\n\x1b[31mapp exe"),
        "evil???31mapp?exe"
    );
    assert_eq!(sanitize_for_log("ünïcode/x"), "?n?code?x");
    let long = "a".repeat(100);
    assert_eq!(sanitize_for_log(&long).len(), 64);
}
