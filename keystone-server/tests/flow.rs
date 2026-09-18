//! End-to-end flow tests against the real router — challenge →
//! exchange → attest → heartbeat → revoke, plus every rejection the
//! spec calls out.

use argon2::password_hash::PasswordHasher;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration, Utc};
use http_body_util::BodyExt;
use keystone_core::{
    mac_heartbeat, mac_response, AccountFile, AccountGrant, AccountRecord, Entitlement, Envelope,
    Expectation, Issuer, Lease,
};
use keystone_server::accounts::LocalAccounts;
use keystone_server::entitlement::StubEntitlementSource;
use keystone_server::state::{ArtifactHashes, ChallengeBook, RateLimiter, RateLimits};
use keystone_server::{build_router, AppState, SessionStore};
use serde_json::{json, Value};
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
        issuer: Arc::new(Issuer::from_bytes(&[7u8; 32])),
        store: SessionStore::new(),
        entitlements,
        challenges: Arc::new(ChallengeBook::new()),
        admin_token_hash: Some(Sha256::digest(ADMIN_TOKEN.as_bytes()).into()),
        challenge_ttl: Duration::seconds(60),
        lease_ttl,
        grace_period: Duration::seconds(60),
        payload_dir: None,
        payload_secret: None,
        downloads: None,
        watermark_secret: None,
        rate_limits: RateLimits::default(),
        rate_limiter: Arc::new(RateLimiter::new()),
        artifact_hashes: Arc::new(ArtifactHashes::new()),
    }
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

/// Mint a server-issued challenge nonce.
async fn get_challenge(app: &axum::Router) -> [u8; 32] {
    let (status, ch) = post(app, "/challenge", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    arr32(&ch, "nonce")
}

struct Session {
    id: Uuid,
    key: [u8; 32],
}

/// Run challenge + exchange; asserts the exchange envelope verifies.
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
    let nonce = get_challenge(app).await;
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
    let session_id: Uuid =
        serde_json::from_value(body_json["session_id"].clone()).unwrap();
    env.verify(
        &state.issuer.verifying_key(),
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

/// Attest with a fresh server challenge and a valid MAC.
async fn attest_ok(
    app: &axum::Router,
    state: &AppState,
    session: &Session,
) -> (Envelope, Lease) {
    let nonce = get_challenge(app).await;
    let mac = mac_response(&session.key, &nonce, b"attest");
    let (status, body) = post(
        app,
        "/attest",
        json!({
            "session_id": session.id,
            "challenge": nonce,
            "process_id": "dev-app.exe",
            "mac": mac,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "attest failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    env.verify(
        &state.issuer.verifying_key(),
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

    // Heartbeat: MAC over DOMAIN_HEARTBEAT + session_id + nonce proves
    // session-key possession; the response is a signed lease renewal.
    let hb_nonce = [22u8; 32];
    let mac = mac_heartbeat(&session.key, &session.id, &hb_nonce);
    let (status, body) = post(
        &app,
        "/heartbeat",
        json!({ "session_id": session.id, "nonce": hb_nonce, "mac": mac }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "heartbeat failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    env.verify(
        &state.issuer.verifying_key(),
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
    let nonce = get_challenge(&app).await;
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
    let nonce = get_challenge(&app).await;
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
    let nonce = get_challenge(&app).await;
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
        json!({ "session_id": session.id, "nonce": nonce, "mac": bad_mac }),
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
    let mac = mac_heartbeat(&session.key, &session.id, &nonce);
    let (status, _) = post(
        &app,
        "/heartbeat",
        json!({ "session_id": session.id, "nonce": nonce, "mac": mac }),
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
    let mac = mac_heartbeat(&session.key, &session.id, &nonce);
    let (status, _) = post(
        &app,
        "/heartbeat",
        json!({ "session_id": session.id, "nonce": nonce, "mac": mac }),
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
    let state = test_state_with(
        Duration::seconds(300),
        Utc::now() + Duration::milliseconds(500),
    );
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    tokio::time::sleep(std::time::Duration::from_millis(600)).await;

    let nonce = [66u8; 32];
    let mac = mac_heartbeat(&session.key, &session.id, &nonce);
    let (status, _) = post(
        &app,
        "/heartbeat",
        json!({ "session_id": session.id, "nonce": nonce, "mac": mac }),
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
    let nonce = get_challenge(&app).await;
    let (status, _) = post(
        &app,
        "/attest",
        json!({
            "session_id": session.id,
            "challenge": nonce,
            "process_id": "dev-app.exe",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Wrong MAC → 401.
    let nonce = get_challenge(&app).await;
    let bad_mac = [0xBBu8; 32];
    let (status, _) = post(
        &app,
        "/attest",
        json!({
            "session_id": session.id,
            "challenge": nonce,
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
    assert!(matches!(view.state, keystone_core::SessionState::Active { .. }));
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
async fn challenge_single_use_and_validation() {
    let state = test_state();
    let app = build_router(state.clone());

    // A nonce the server never issued → 401 bad_challenge — transient,
    // not a session verdict.
    let garbage = [0xFFu8; 32];
    let hwid = [9u8; 32];
    let (status, _) = post(
        &app,
        "/exchange",
        json!({
            "account": ACCOUNT,
            "secret": SECRET,
            "product": PRODUCT,
            "hwid": hwid,
            "challenge": garbage,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A real nonce works once…
    let nonce = get_challenge(&app).await;
    let (status, _) = post(
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
    assert_eq!(status, StatusCode::OK);

    // …and is rejected on reuse → 401 bad_challenge.
    let (status, _) = post(
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
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_challenge_rejected() {
    let mut state = test_state();
    state.challenge_ttl = Duration::seconds(-1);
    let app = build_router(state);

    let (status, ch) = post(&app, "/challenge", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let nonce = arr32(&ch, "nonce");

    let hwid = [9u8; 32];
    let (status, _) = post(
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
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_session_attest_and_heartbeat() {
    let state = test_state();
    let app = build_router(state.clone());

    // Attest against a session that doesn't exist → 404 (challenge is
    // valid; the session lookup is what fails).
    let nonce = get_challenge(&app).await;
    let mac = [0xCCu8; 32];
    let (status, _) = post(
        &app,
        "/attest",
        json!({
            "session_id": Uuid::new_v4(),
            "challenge": nonce,
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
        json!({ "session_id": Uuid::new_v4(), "nonce": hb_nonce, "mac": mac }),
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
    let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
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

async fn heartbeat_once(app: &axum::Router, session: &Session, nonce: [u8; 32]) -> (StatusCode, Value) {
    let mac = mac_heartbeat(&session.key, &session.id, &nonce);
    post(
        app,
        "/heartbeat",
        json!({ "session_id": session.id, "nonce": nonce, "mac": mac }),
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
    assert_eq!(status, StatusCode::FORBIDDEN, "pulled grant must kill: {status}");
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
            accounts: vec![file_record(ACCOUNT, SECRET, vec![file_grant(PRODUCT, extended)])],
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

/// A stale challenge on attest is a transient 401 bad_challenge — not
/// the 403 verdict it used to share with real denials.
#[tokio::test]
async fn attest_stale_challenge_is_bad_challenge() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let nonce = get_challenge(&app).await;
    let mac = mac_response(&session.key, &nonce, b"attest");
    let req = json!({
        "session_id": session.id,
        "challenge": nonce,
        "process_id": "dev-app.exe",
        "mac": mac,
    });
    // First use succeeds…
    let (status, _) = post(&app, "/attest", req.clone()).await;
    assert_eq!(status, StatusCode::OK);
    // …and the spent nonce is a 401 bad_challenge, not a 403.
    let (status, body) = post(&app, "/attest", req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "bad_challenge");

    // A nonce the server never issued is the same transient failure.
    let (status, body) = post(
        &app,
        "/attest",
        json!({
            "session_id": session.id,
            "challenge": vec![0xEEu8; 32],
            "process_id": "dev-app.exe",
            "mac": mac,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "bad_challenge");

    // The session itself is untouched — a bad challenge is not a verdict.
    let view = state.store.get(&session.id).unwrap();
    assert!(matches!(view.state, keystone_core::SessionState::Active { .. }));
}

/// Past the sliding-window limit the route answers 429 rate_limited.
#[tokio::test]
async fn challenge_rate_limited_after_burst() {
    let mut state = test_state();
    state.rate_limits.challenge_per_ip = 3;
    let app = build_router(state);

    for _ in 0..3 {
        let (status, _) = post(&app, "/challenge", json!({})).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, body) = post(&app, "/challenge", json!({})).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");
}

/// N parallel heartbeats on one session with the same nonce: exactly
/// one consume wins, the rest are 409 — no double-spend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_heartbeats_single_consume() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    let nonce = [0xA5u8; 32];
    let mac = mac_heartbeat(&session.key, &session.id, &nonce);
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let app = app.clone();
        set.spawn(async move {
            post(
                &app,
                "/heartbeat",
                json!({ "session_id": session.id, "nonce": nonce, "mac": mac }),
            )
            .await
            .0
        });
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

/// Sessions are in-memory by design: a restarted server has no record
/// of the session, so the client sees 404 and must treat the session
/// as dead and re-exchange. This test documents that contract.
#[tokio::test]
async fn restart_recovery_is_reexchange() {
    let state = test_state();
    let app = build_router(state.clone());
    let session = establish_session(&app, &state).await;

    // "Restart": a fresh store behind a fresh router — the session
    // record is gone.
    let restarted = build_router(test_state());
    let (status, _) = heartbeat_once(&restarted, &session, [0xB1u8; 32]).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "restarted server must 404");
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
    let nonce = get_challenge(&app).await;
    let mac = mac_response(&session.key, &nonce, b"attest");
    let (status, body) = post(
        &app,
        "/attest",
        json!({
            "session_id": session.id,
            "challenge": nonce,
            "process_id": "dev-app.exe",
            "mac": mac,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "session_not_active");

    // Heartbeat: valid MAC — same denial.
    let hb_nonce = [0x44u8; 32];
    let hb_mac = mac_heartbeat(&session.key, &session.id, &hb_nonce);
    let (status, body) = post(
        &app,
        "/heartbeat",
        json!({ "session_id": session.id, "nonce": hb_nonce, "mac": hb_mac }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "session_not_active");
}

/// A failed exchange still burns the challenge: the nonce is consumed
/// before authentication runs, so a bad-credential attempt must leave
/// the nonce spent — reuse is bad_challenge, not another auth try.
#[tokio::test]
async fn bad_credential_exchange_burns_challenge() {
    let state = test_state();
    let app = build_router(state);
    let nonce = get_challenge(&app).await;
    let hwid = [9u8; 32];

    let (status, _) = post(
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

    // Correct credentials, same nonce → bad_challenge, not a session.
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
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "bad_challenge");
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
        let nonce = get_challenge(&app).await;
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
        let nonce = get_challenge(&app).await;
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

/// HWID anomaly is a signal, not a gate (DESIGN.md: assume spoofable):
/// a second exchange for the same account with a different fingerprint
/// inside the window must still return 200.
#[tokio::test]
async fn hwid_anomaly_does_not_gate_exchange() {
    let state = test_state();
    let app = build_router(state.clone());
    let _s1 = establish_session(&app, &state).await; // hwid [9;32]

    let nonce = get_challenge(&app).await;
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
    let mac_for_a = mac_heartbeat(&a.key, &a.id, &nonce);
    let (status, _) = post(
        &app,
        "/heartbeat",
        json!({ "session_id": b.id, "nonce": nonce, "mac": mac_for_a }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // B is untouched — a foreign MAC is not a verdict on the session.
    let view = state.store.get(&b.id).unwrap();
    assert!(matches!(view.state, keystone_core::SessionState::Active { .. }));
}

/// The stub backend returns grants regardless of expiry — the
/// exchange's own `now >= grant.expires_at` check is the only guard.
/// An expired grant must be 410, not a session.
#[tokio::test]
async fn exchange_with_expired_grant_is_gone() {
    let state = test_state_with(
        Duration::seconds(300),
        Utc::now() - Duration::seconds(1),
    );
    let app = build_router(state);
    let nonce = get_challenge(&app).await;
    let (status, _) = post(
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
    assert_eq!(status, StatusCode::GONE);
}
