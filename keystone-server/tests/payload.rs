//! Payload route tests: POST /payload (signed manifest + wrapped
//! artifact key) and GET /payload/{product}/{version} (the sealed
//! blob), plus every rejection the session gate must produce.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use keystone_core::{
    Entitlement, Envelope, Expectation, Issuer, KeyWrap, KeystoneError, RequestBinding,
    SessionState, SignedManifest, TrustedIssuers, artifact_context, artifact_key_for,
    decrypt_artifact, mac_request, seal_artifact, unwrap_artifact_key,
};
use keystone_server::downloads::DownloadLog;
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
const VERSION: &str = "1.0.0";
const PAYLOAD_BYTES: &[u8] = b"keystone test payload blob";
const PAYLOAD_SECRET: [u8; 32] = [0x5Au8; 32];
/// The server's live payload epoch — what artifacts are sealed under.
const EPOCH: u32 = 0;
/// The epoch both sides fix the payload MAC bodies to (the client
/// can't know the live one before the manifest arrives).
const MAC_EPOCH: u32 = 0;

fn test_state(payload_dir: Option<PathBuf>) -> AppState {
    test_state_full(payload_dir, Some(PAYLOAD_SECRET))
}

fn test_state_full(payload_dir: Option<PathBuf>, secret: Option<[u8; 32]>) -> AppState {
    let entitlements = Arc::new(StubEntitlementSource::new(vec![(
        ACCOUNT.to_string(),
        SECRET.to_string(),
        vec![Entitlement {
            account: ACCOUNT.to_string(),
            product: PRODUCT.to_string(),
            expires_at: Utc::now() + Duration::days(30),
            features: vec!["esp".to_string(), "aimbot".to_string()],
        }],
    )]));
    AppState {
        issuer: Arc::new(Issuer::from_seed(&[7u8; 32], 1)),
        store: SessionStore::new(),
        entitlements,
        admin_token_hash: None,
        lease_ttl: Duration::seconds(300),
        grace_period: Duration::seconds(60),
        payload_dir,
        payload_secret: secret,
        payload_epoch: EPOCH,
        downloads: None,
        watermark_secret: None,
        rate_limits: RateLimits::default(),
        rate_limiter: Arc::new(RateLimiter::new()),
        artifact_hashes: Arc::new(ArtifactHashes::new()),
        revoked_key_ids: Arc::new(RwLock::new(BTreeSet::new())),
    }
}

/// The trust root a client of this server would bake in.
fn issuers(state: &AppState) -> TrustedIssuers {
    TrustedIssuers::single(state.issuer.key_id(), state.issuer.verifying_key())
}

/// A payload dir holding the sealed release blob for product-version.
fn payload_dir_with(product: &str, version: &str, plaintext: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keystone-payload-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let context = artifact_context(product, version, EPOCH);
    let sealed = seal_artifact(&PAYLOAD_SECRET, &context, plaintext).unwrap();
    std::fs::write(dir.join(format!("{product}-{version}.bin")), sealed).unwrap();
    dir
}

/// A payload dir holding raw bytes verbatim — for unsealed/tampered
/// artifact tests that must bypass the sealer.
fn payload_dir_raw(product: &str, version: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keystone-payload-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{product}-{version}.bin")), bytes).unwrap();
    dir
}

async fn request(
    app: &axum::Router,
    method: &str,
    path: &str,
    auth: Option<String>,
    body: Option<Value>,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(auth) = auth {
        builder = builder.header("authorization", auth);
    }
    let req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => builder.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec())
}

async fn post(app: &axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let (status, bytes) = request(app, "POST", path, None, Some(body)).await;
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

struct Session {
    id: Uuid,
    key: [u8; 32],
}

/// Exchange against the dev account with a client-minted nonce.
async fn establish_session(app: &axum::Router) -> Session {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let (status, body) = post(
        app,
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
    assert_eq!(status, StatusCode::OK, "exchange failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    let body_json: Value = serde_json::from_slice(&env.body).unwrap();
    Session {
        id: serde_json::from_value(body_json["session_id"].clone()).unwrap(),
        key: arr32(&body_json, "session_key"),
    }
}

/// A well-formed POST /payload request for product:version, stamped
/// with the current time.
fn fetch_req(session: &Session, product: &str, version: &str, nonce: [u8; 32]) -> Value {
    let issued_at = Utc::now();
    let mac_body = [
        b"payload.fetch:".as_slice(),
        &artifact_context(product, version, MAC_EPOCH),
    ]
    .concat();
    let mac = mac_request(
        &session.key,
        &RequestBinding {
            session_id: &session.id,
            nonce: &nonce,
            issued_at,
            context: &mac_body,
        },
    );
    json!({
        "session_id": session.id,
        "product": product,
        "version": version,
        "nonce": nonce,
        "issued_at": issued_at,
        "mac": mac,
    })
}

/// The Authorization header GET /payload expects:
/// `Keystone <session_id>:<nonce_hex>:<issued_at_ms>:<mac_hex>`.
fn blob_auth(session: &Session, product: &str, version: &str, nonce: [u8; 32]) -> String {
    let issued_at = Utc::now();
    let mac_body = [
        b"payload.download:".as_slice(),
        &artifact_context(product, version, MAC_EPOCH),
    ]
    .concat();
    let mac = mac_request(
        &session.key,
        &RequestBinding {
            session_id: &session.id,
            nonce: &nonce,
            issued_at,
            context: &mac_body,
        },
    );
    format!(
        "Keystone {}:{}:{}:{}",
        session.id,
        hex::encode(nonce),
        issued_at.timestamp_millis(),
        hex::encode(mac)
    )
}

#[tokio::test]
async fn payload_fetch_happy_path() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir.clone()));
    let app = build_router(state.clone());
    let session = establish_session(&app).await;

    let nonce = [0x42u8; 32];
    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, nonce),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "payload fetch failed: {body}");

    let env: Envelope = serde_json::from_value(body).unwrap();
    env.verify(
        &issuers(&state),
        &Expectation {
            challenge: &nonce,
            session_id: &session.id,
            audience: "keystone-app",
            operation: "payload.fetch",
            now: Utc::now(),
        },
    )
    .expect("payload envelope must verify");

    let body_json: Value = serde_json::from_slice(&env.body).unwrap();
    let signed: SignedManifest = serde_json::from_value(body_json["manifest"].clone()).unwrap();
    let manifest = signed
        .verify(&issuers(&state), Utc::now())
        .expect("manifest must verify");
    assert_eq!(manifest.product, PRODUCT);
    assert_eq!(manifest.version, VERSION);
    // The manifest attests the plaintext hash — what runs, not what
    // sits on disk.
    manifest.verify_payload(PAYLOAD_BYTES).unwrap();
    assert!(manifest.has_feature("esp", Utc::now()));
    assert!(manifest.has_feature("aimbot", Utc::now()));
    assert!(!manifest.has_feature("fly", Utc::now()));

    // The wrap opens only under this session's key + this request's
    // nonce — a captured wrap is dead material anywhere else.
    let wrap: KeyWrap = serde_json::from_value(body_json["payload_key_wrap"].clone()).unwrap();
    let artifact_key = unwrap_artifact_key(&session.key, &nonce, &wrap)
        .expect("wrap must open under the session key");
    // And the unwrapped key actually decrypts the sealed blob.
    let sealed = std::fs::read(dir.join(format!("{PRODUCT}-{VERSION}.bin"))).unwrap();
    let plaintext = decrypt_artifact(&artifact_key, &sealed).unwrap();
    assert_eq!(plaintext, PAYLOAD_BYTES);
    // The same key is derivable server-side from the artifact secret.
    let expected = artifact_key_for(
        &PAYLOAD_SECRET,
        &artifact_context(PRODUCT, VERSION, EPOCH),
        &sealed,
    )
    .unwrap();
    assert_eq!(artifact_key, expected);
}

#[tokio::test]
async fn payload_fetch_wrong_mac_rejected() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        json!({
            "session_id": session.id,
            "product": PRODUCT,
            "version": VERSION,
            "nonce": vec![7u8; 32],
            "issued_at": Utc::now(),
            "mac": vec![0u8; 32],
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "bad MAC must be 401: {body}"
    );
}

#[tokio::test]
async fn payload_fetch_dead_session_rejected() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state.clone());
    let session = establish_session(&app).await;
    assert!(state.store.revoke(&session.id));

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    // A valid MAC must never resurrect a revoked session.
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "dead session must be 403: {body}"
    );
}

#[tokio::test]
async fn payload_fetch_wrong_product_rejected() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;

    // A MAC minted for dev-product can't be transplanted onto another
    // product — the MAC body binds product:version.
    let nonce = [0x42u8; 32];
    let issued_at = Utc::now();
    let mac = mac_request(
        &session.key,
        &RequestBinding {
            session_id: &session.id,
            nonce: &nonce,
            issued_at,
            context: &[
                b"payload.fetch:".as_slice(),
                &artifact_context(PRODUCT, VERSION, MAC_EPOCH),
            ]
            .concat(),
        },
    );
    let (status, body) = post(
        &app,
        "/payload",
        json!({
            "session_id": session.id,
            "product": "other-product",
            "version": VERSION,
            "nonce": nonce,
            "issued_at": issued_at,
            "mac": mac,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "transplanted MAC must be 401: {body}"
    );

    // A correctly-bound MAC for a product the account isn't entitled
    // to is a denial, not a forgery.
    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, "other-product", VERSION, [0x43u8; 32]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "unentitled product must be 403: {body}"
    );
}

#[tokio::test]
async fn payload_fetch_unconfigured_dir_unavailable() {
    let state = test_state(None);
    let app = build_router(state);
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "unset payload dir must be 503: {body}"
    );
}

#[tokio::test]
async fn payload_fetch_missing_secret_unavailable() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state_full(Some(dir), None);
    let app = build_router(state);
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    // A dir without the secret can serve only ciphertext nobody can
    // attest — the routes are closed, same as no dir at all.
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "missing payload secret must be 503: {body}"
    );
}

#[tokio::test]
async fn payload_fetch_replayed_nonce_rejected() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;

    let nonce = [0x42u8; 32];
    let req = fetch_req(&session, PRODUCT, VERSION, nonce);
    let (status, _) = post(&app, "/payload", req.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post(&app, "/payload", req).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "replayed nonce must be 409: {body}"
    );
}

#[tokio::test]
async fn payload_fetch_replay_survives_lease_renewal() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;

    let nonce = [0x42u8; 32];
    let req = fetch_req(&session, PRODUCT, VERSION, nonce);
    let (status, _) = post(&app, "/payload", req.clone()).await;
    assert_eq!(status, StatusCode::OK);

    // Renew the lease — the consumed nonce must outlive the rolling
    // lease window or the captured MAC replays after every heartbeat.
    let hb_nonce = [0x77u8; 32];
    let hb_issued_at = Utc::now();
    let hb_mac = mac_request(
        &session.key,
        &RequestBinding {
            session_id: &session.id,
            nonce: &hb_nonce,
            issued_at: hb_issued_at,
            context: b"heartbeat",
        },
    );
    let (status, body) = post(
        &app,
        "/heartbeat",
        json!({"session_id": session.id, "nonce": hb_nonce, "issued_at": hb_issued_at, "mac": hb_mac}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "heartbeat failed: {body}");

    let (status, body) = post(&app, "/payload", req).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "nonce replayed after renewal must be 409: {body}"
    );
}

#[tokio::test]
async fn payload_fetch_missing_artifact_is_transient() {
    // Dir exists and is configured — the artifact just isn't there.
    let dir = std::env::temp_dir().join(format!("keystone-payload-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The code distinguishes "artifact missing" from "unknown
    // session" — the client must not kill the session over this.
    assert_eq!(body["code"], "artifact_not_found");
}

#[tokio::test]
async fn payload_fetch_unsealed_artifact_refused() {
    // Raw plaintext sitting in the payload dir is a packaging bug —
    // the server refuses to attest it rather than sign a manifest for
    // bytes that were never sealed.
    let dir = payload_dir_raw(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "artifact_invalid");
}

#[tokio::test]
async fn payload_fetch_tampered_artifact_refused() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    // Flip a ciphertext byte — the Poly1305 tag must catch it.
    let path = dir.join(format!("{PRODUCT}-{VERSION}.bin"));
    let mut sealed = std::fs::read(&path).unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;
    std::fs::write(&path, sealed).unwrap();

    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "artifact_invalid");
}

#[tokio::test]
async fn grace_session_payload_request_is_transient() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state.clone());
    let session = establish_session(&app).await;

    // Force the server-side record into Grace — the session isn't
    // dead, it's on borrowed time, and the client must read that as
    // transient rather than a verdict.
    state
        .store
        .with_mut(&session.id, |rec| {
            if let SessionState::Active { lease } = &rec.state {
                rec.state = SessionState::Grace {
                    lease: lease.clone(),
                    deadline: Utc::now() + Duration::seconds(30),
                };
            }
        })
        .expect("session must exist");

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "session_not_active");
}

#[tokio::test]
async fn payload_blob_download_and_auth() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;

    // Happy path: MAC'd GET returns the sealed blob, which decrypts
    // under the artifact key.
    let auth = blob_auth(&session, PRODUCT, VERSION, [0xABu8; 32]);
    let (status, bytes) = request(
        &app,
        "GET",
        &format!("/payload/{PRODUCT}/{VERSION}"),
        Some(auth),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(bytes, PAYLOAD_BYTES, "blob must be sealed on the wire");
    let key = artifact_key_for(
        &PAYLOAD_SECRET,
        &artifact_context(PRODUCT, VERSION, EPOCH),
        &bytes,
    )
    .unwrap();
    assert_eq!(decrypt_artifact(&key, &bytes).unwrap(), PAYLOAD_BYTES);

    // No header → 401.
    let (status, _) = request(
        &app,
        "GET",
        &format!("/payload/{PRODUCT}/{VERSION}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A MAC bound to a different artifact must not transplant.
    let auth = blob_auth(&session, "other-product", VERSION, [0xACu8; 32]);
    let (status, _) = request(
        &app,
        "GET",
        &format!("/payload/{PRODUCT}/{VERSION}"),
        Some(auth),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Missing artifact → 404 with the transient marker.
    let auth = blob_auth(&session, PRODUCT, "9.9.9", [0xADu8; 32]);
    let (status, bytes) = request(
        &app,
        "GET",
        &format!("/payload/{PRODUCT}/9.9.9"),
        Some(auth),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "artifact_not_found");
}

/// The download header carries `issued_at` as its third segment. The
/// pre-timestamp three-segment shape is not accepted — the stamp is
/// part of the contract, not an optional extra — and the four-segment
/// shape is what serves the blob.
#[tokio::test]
async fn payload_download_header_carries_issued_at() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;
    let path = format!("/payload/{PRODUCT}/{VERSION}");
    let mac_body = [
        b"payload.download:".as_slice(),
        &artifact_context(PRODUCT, VERSION, MAC_EPOCH),
    ]
    .concat();

    let nonce = [0xAEu8; 32];
    let mac = mac_request(
        &session.key,
        &RequestBinding {
            session_id: &session.id,
            nonce: &nonce,
            issued_at: Utc::now(),
            context: &mac_body,
        },
    );
    let legacy = format!(
        "Keystone {}:{}:{}",
        session.id,
        hex::encode(nonce),
        hex::encode(mac)
    );
    let (status, _) = request(&app, "GET", &path, Some(legacy), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let auth = blob_auth(&session, PRODUCT, VERSION, [0xAFu8; 32]);
    let (status, _) = request(&app, "GET", &path, Some(auth), None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn tampered_manifest_signature_fails_verification() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state.clone());
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let env: Envelope = serde_json::from_value(body).unwrap();
    let body_json: Value = serde_json::from_slice(&env.body).unwrap();
    let mut signed: SignedManifest = serde_json::from_value(body_json["manifest"].clone()).unwrap();

    // Flip a bit the signature covers — verification must fail.
    signed.manifest.version = "9.9.9".to_string();
    let err = signed.verify(&issuers(&state), Utc::now()).unwrap_err();
    assert!(matches!(err, KeystoneError::InvalidSignature));
}

/// The build id written by `xtask seal` into the `.build` sidecar must
/// surface in the signed manifest the server issues.
#[tokio::test]
async fn served_manifest_carries_build_id() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    std::fs::write(
        dir.join(format!("{PRODUCT}-{VERSION}.build")),
        "release-2026-09",
    )
    .unwrap();
    let state = test_state(Some(dir));
    let app = build_router(state.clone());
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x77u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let env: Envelope = serde_json::from_value(body).unwrap();
    let body_json: Value = serde_json::from_slice(&env.body).unwrap();
    let signed: SignedManifest = serde_json::from_value(body_json["manifest"].clone()).unwrap();
    let manifest = signed
        .verify(&issuers(&state), Utc::now())
        .expect("manifest must verify");
    assert_eq!(manifest.build_id, "release-2026-09");
}

/// A fetch + download must append one JSONL record per route, with the
/// account pseudonymized — stable for one account, distinct across
/// accounts, never the raw account string.
#[tokio::test]
async fn download_log_records_fetch_and_blob() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    std::fs::write(dir.join(format!("{PRODUCT}-{VERSION}.build")), "b1").unwrap();
    let log_path = dir.join("downloads.jsonl");
    let mut state = test_state(Some(dir));
    // No dedicated watermark secret in tests — the payload secret is
    // the documented fallback pseudonym key.
    state.downloads = Some(DownloadLog::open(&log_path, PAYLOAD_SECRET).unwrap());
    let app = build_router(state);
    let session = establish_session(&app).await;

    let (status, _) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x51u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let auth = blob_auth(&session, PRODUCT, VERSION, [0x52u8; 32]);
    let (status, _) = request(
        &app,
        "GET",
        &format!("/payload/{PRODUCT}/{VERSION}"),
        Some(auth),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let lines: Vec<Value> = std::fs::read_to_string(&log_path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2, "one record per served route");
    assert_eq!(lines[0]["route"], "manifest_issued");
    assert_eq!(lines[1]["route"], "blob_served");
    for line in &lines {
        assert_eq!(line["product"], PRODUCT);
        assert_eq!(line["version"], VERSION);
        assert_eq!(line["build_id"], "b1");
        assert!(line["ts"].is_string());
        assert!(line["session_tag"].is_string());
    }
    // Same session → same session tag on both records.
    assert_eq!(lines[0]["session_tag"], lines[1]["session_tag"]);

    // The pseudonym is the HMAC of the account under the secret —
    // recompute it independently rather than trusting the log's own
    // function.
    let pseudonym = lines[0]["account_pseudonym"].as_str().unwrap();
    assert_ne!(pseudonym, ACCOUNT);
    let mut mac = Hmac::<Sha256>::new_from_slice(&PAYLOAD_SECRET).unwrap();
    mac.update(ACCOUNT.as_bytes());
    assert_eq!(pseudonym, hex::encode(mac.finalize().into_bytes()));
    let mut mac = Hmac::<Sha256>::new_from_slice(&PAYLOAD_SECRET).unwrap();
    mac.update(b"other-account");
    assert_ne!(pseudonym, hex::encode(mac.finalize().into_bytes()));
}

/// Every manifest fetch gets a fresh signed download_id — the
/// watermark that ties a leaked manifest back to one download.
#[tokio::test]
async fn manifest_download_id_is_per_request_and_signed() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let mut state = test_state(Some(dir));
    state.watermark_secret = Some([0x77u8; 32]);
    let app = build_router(state.clone());
    let session = establish_session(&app).await;

    let mut ids = Vec::new();
    for nonce in [[0x61u8; 32], [0x62u8; 32]] {
        let (status, body) = post(
            &app,
            "/payload",
            fetch_req(&session, PRODUCT, VERSION, nonce),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "fetch failed: {body}");
        let env: Envelope = serde_json::from_value(body).unwrap();
        let body_json: Value = serde_json::from_slice(&env.body).unwrap();
        let signed: SignedManifest = serde_json::from_value(body_json["manifest"].clone()).unwrap();
        // The id is inside the signature — verify() passing means the
        // download_id is attested, not just present.
        let manifest = signed
            .verify(&issuers(&state), Utc::now())
            .expect("manifest must verify");
        assert_eq!(manifest.download_id.len(), 64, "download_id is hex sha256");
        ids.push(manifest.download_id.clone());
    }
    assert_ne!(ids[0], ids[1], "download_id must differ per request");
}

/// A `.sha256` sidecar supplies the plaintext hash without decrypting:
/// a blob that would fail to unseal still gets a manifest when the
/// sidecar is present.
#[tokio::test]
async fn sha256_sidecar_skips_decrypt() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let plaintext_hash: [u8; 32] = Sha256::digest(PAYLOAD_BYTES).into();
    std::fs::write(
        dir.join(format!("{PRODUCT}-{VERSION}.sha256")),
        hex::encode(plaintext_hash),
    )
    .unwrap();
    // Corrupt the sealed blob — if the server decrypted, this fetch
    // would be 422 artifact_invalid.
    let path = dir.join(format!("{PRODUCT}-{VERSION}.bin"));
    let mut sealed = std::fs::read(&path).unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;
    std::fs::write(&path, sealed).unwrap();

    let state = test_state(Some(dir));
    let app = build_router(state.clone());
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x63u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sidecar fetch failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    let body_json: Value = serde_json::from_slice(&env.body).unwrap();
    let signed: SignedManifest = serde_json::from_value(body_json["manifest"].clone()).unwrap();
    let manifest = signed
        .verify(&issuers(&state), Utc::now())
        .expect("manifest must verify");
    assert_eq!(manifest.sha256, plaintext_hash);
}

/// Without a sidecar the hash is computed once and cached by
/// (path, mtime): a second fetch must not re-decrypt — proven by
/// corrupting the blob while pinning its mtime, which a re-decrypt
/// would catch and a cache hit ignores.
#[tokio::test]
async fn plaintext_hash_cached_by_mtime() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let path = dir.join(format!("{PRODUCT}-{VERSION}.bin"));
    let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();

    let state = test_state(Some(dir));
    let app = build_router(state.clone());
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x64u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "first fetch failed: {body}");

    // Corrupt the blob but restore its mtime — the cache key is
    // unchanged, so a hit must serve the original hash.
    let mut sealed = std::fs::read(&path).unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;
    std::fs::write(&path, sealed).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x65u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "cached fetch failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    let body_json: Value = serde_json::from_slice(&env.body).unwrap();
    let signed: SignedManifest = serde_json::from_value(body_json["manifest"].clone()).unwrap();
    let manifest = signed
        .verify(&issuers(&state), Utc::now())
        .expect("manifest must verify");
    manifest.verify_payload(PAYLOAD_BYTES).unwrap();
}

/// The Authorization header parser must reject every malformed shape
/// with 401 — wrong scheme, extra colons, short hex — before any
/// session lookup happens.
#[tokio::test]
async fn payload_blob_malformed_auth_headers_rejected() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;
    let path = format!("/payload/{PRODUCT}/{VERSION}");

    let nonce_hex = hex::encode([0xABu8; 32]);
    let mac_hex = hex::encode([0xCDu8; 32]);
    let ms = Utc::now().timestamp_millis();
    let cases = [
        // Wrong scheme.
        format!("Bearer {}:{}:{}:{}", session.id, nonce_hex, ms, mac_hex),
        // Missing scheme entirely.
        format!("{}:{}:{}:{}", session.id, nonce_hex, ms, mac_hex),
        // Extra colon-separated field.
        format!(
            "Keystone {}:{}:{}:{}:extra",
            session.id, nonce_hex, ms, mac_hex
        ),
        // Short hex for the nonce (31 bytes).
        format!(
            "Keystone {}:{}:{}:{}",
            session.id,
            &nonce_hex[..62],
            ms,
            mac_hex
        ),
        // Short hex for the MAC.
        format!(
            "Keystone {}:{}:{}:{}",
            session.id,
            nonce_hex,
            ms,
            &mac_hex[..62]
        ),
        // Non-hex nonce.
        format!(
            "Keystone {}:{}:{}:{}",
            session.id,
            "zz".repeat(32),
            ms,
            mac_hex
        ),
        // Non-numeric timestamp.
        format!(
            "Keystone {}:{}:{}:{}",
            session.id, nonce_hex, "soon", mac_hex
        ),
        // Timestamp beyond what a DateTime can hold.
        format!(
            "Keystone {}:{}:{}:{}",
            session.id,
            nonce_hex,
            i64::MAX,
            mac_hex
        ),
        // Missing fields.
        format!("Keystone {}", session.id),
    ];
    for auth in cases {
        let (status, _) = request(&app, "GET", &path, Some(auth.clone()), None).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "malformed auth {auth:?} must be 401"
        );
    }
}

/// An artifact over the 256MB cap is refused on its declared size —
/// the server must never read it into memory. A sparse file proves
/// the metadata check fires before the read.
#[tokio::test]
async fn oversized_artifact_rejected() {
    let dir = std::env::temp_dir().join(format!("keystone-payload-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{PRODUCT}-{VERSION}.bin"));
    // Declared size past the cap without writing the bytes.
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(keystone_core::MAX_ARTIFACT_BYTES + 1).unwrap();
    drop(f);

    let state = test_state(Some(dir));
    let app = build_router(state);
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "artifact_invalid");
}

/// The manifest never attests a window the lease or the grant doesn't
/// cover: expires_at must be exactly min(lease, grant), and the
/// envelope carrying it must expire at the same instant.
#[tokio::test]
async fn manifest_expiry_is_capped_by_lease_and_grant() {
    // Case 1: grant < lease — the grant caps the manifest.
    let grant_expiry = Utc::now() + Duration::seconds(120);
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let mut state = test_state(Some(dir));
    state.entitlements = Arc::new(StubEntitlementSource::new(vec![(
        ACCOUNT.to_string(),
        SECRET.to_string(),
        vec![Entitlement {
            account: ACCOUNT.to_string(),
            product: PRODUCT.to_string(),
            expires_at: grant_expiry,
            features: vec!["esp".to_string()],
        }],
    )]));
    let app = build_router(state.clone());
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "fetch failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    let body_json: Value = serde_json::from_slice(&env.body).unwrap();
    let signed: SignedManifest = serde_json::from_value(body_json["manifest"].clone()).unwrap();
    // The lease (300s) outlives the grant (120s) — grant wins.
    assert_eq!(signed.manifest.expires_at, grant_expiry);
    assert_eq!(env.expires_at, grant_expiry);

    // Case 2: lease < grant — the lease caps the manifest.
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let mut state = test_state(Some(dir));
    state.lease_ttl = Duration::seconds(60);
    let app = build_router(state.clone());
    let session = establish_session(&app).await;
    let lease_expiry = match &state.store.get(&session.id).unwrap().state {
        SessionState::Active { lease } => lease.expires_at,
        other => panic!("expected Active session, got {other:?}"),
    };

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "fetch failed: {body}");
    let env: Envelope = serde_json::from_value(body).unwrap();
    let body_json: Value = serde_json::from_slice(&env.body).unwrap();
    let signed: SignedManifest = serde_json::from_value(body_json["manifest"].clone()).unwrap();
    assert_eq!(signed.manifest.expires_at, lease_expiry);
    assert_eq!(env.expires_at, lease_expiry);
}

/// Both payload routes carry a per-session sliding-window limit, with
/// separate buckets: throttling the manifest fetch leaves the blob
/// download untouched and vice versa. 429 is transient — the session
/// stays alive.
#[tokio::test]
async fn payload_routes_rate_limited_per_session() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let mut state = test_state(Some(dir));
    state.rate_limits.payload_fetch_per_session = 2;
    state.rate_limits.payload_download_per_session = 1;
    let app = build_router(state.clone());
    let session = establish_session(&app).await;

    for nonce in [[0x71u8; 32], [0x72u8; 32]] {
        let (status, body) = post(
            &app,
            "/payload",
            fetch_req(&session, PRODUCT, VERSION, nonce),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x73u8; 32]),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate_limited");

    // The download bucket is its own: one succeeds, the next is 429.
    let path = format!("/payload/{PRODUCT}/{VERSION}");
    let auth = blob_auth(&session, PRODUCT, VERSION, [0x74u8; 32]);
    let (status, _) = request(&app, "GET", &path, Some(auth), None).await;
    assert_eq!(status, StatusCode::OK);
    let auth = blob_auth(&session, PRODUCT, VERSION, [0x75u8; 32]);
    let (status, bytes) = request(&app, "GET", &path, Some(auth), None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "rate_limited");

    assert!(matches!(
        state.store.get(&session.id).unwrap().state,
        SessionState::Active { .. }
    ));
}

/// The artifact key derives from the server's epoch: a blob sealed
/// under epoch 0 does not unseal on a server running epoch 1, so a
/// rotation really does re-key the release — while the request MAC,
/// which the client computes without knowing the epoch, still passes
/// the gate.
#[tokio::test]
async fn payload_epoch_rekeys_artifacts() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let mut state = test_state(Some(dir));
    state.payload_epoch = 1;
    let app = build_router(state);
    let session = establish_session(&app).await;

    let (status, body) = post(
        &app,
        "/payload",
        fetch_req(&session, PRODUCT, VERSION, [0x42u8; 32]),
    )
    .await;
    // Past the gate (not 401), but the epoch-0 blob is undecryptable
    // under epoch 1 — a corrupt artifact, not a client problem.
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "artifact_invalid");
}
