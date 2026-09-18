//! Handoff tests: the client seals session material for the app it
//! launches, and the app opens it and attests against the real server
//! — the same wire-level harness as client_flow.rs.

use std::sync::Arc;

use chrono::{Duration, Utc};
use ed25519_dalek::VerifyingKey;
use keystone_client::{ClientError, ClientSession, KeystoneClient};
use keystone_core::{Entitlement, Issuer, KeystoneError};
use keystone_server::entitlement::StubEntitlementSource;
use keystone_server::state::{ArtifactHashes, ChallengeBook, RateLimiter, RateLimits};
use keystone_server::{AppState, SessionStore, build_router};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const ACCOUNT: &str = "dev";
const SECRET: &str = "devpass";
const PRODUCT: &str = "dev-product";
const ADMIN_TOKEN: &str = "test-admin-token";
const ISSUER_SEED: [u8; 32] = [7u8; 32];
const PROCESS_ID: &str = "keystone-app-test";

fn test_state(lease_ttl: Duration, grace_period: Duration) -> AppState {
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
        issuer: Arc::new(Issuer::from_bytes(&ISSUER_SEED)),
        store: SessionStore::new(),
        entitlements,
        challenges: Arc::new(ChallengeBook::new()),
        admin_token_hash: Some(Sha256::digest(ADMIN_TOKEN.as_bytes()).into()),
        challenge_ttl: Duration::seconds(60),
        lease_ttl,
        grace_period,
        payload_dir: None,
        payload_secret: None,
        downloads: None,
        watermark_secret: None,
        rate_limits: RateLimits::default(),
        rate_limiter: Arc::new(RateLimiter::default()),
        artifact_hashes: Arc::new(ArtifactHashes::default()),
    }
}

async fn spawn_server(state: AppState) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

fn pinned_key() -> VerifyingKey {
    Issuer::from_bytes(&ISSUER_SEED).verifying_key()
}

fn client_for(base_url: &str) -> KeystoneClient {
    KeystoneClient::new_insecure(base_url, pinned_key()).unwrap()
}

/// The launcher half: exchange, then seal a handoff for the app.
async fn exchanged_session(base_url: &str) -> ClientSession {
    client_for(base_url)
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .expect("exchange")
}

#[tokio::test]
async fn handoff_roundtrip_yields_identical_session_material() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let session = exchanged_session(&base_url).await;
    let (blob, key) = session
        .make_handoff(PROCESS_ID, Duration::seconds(60))
        .expect("make_handoff");
    let mut app = ClientSession::from_handoff(&key, &blob, PROCESS_ID, Utc::now())
        .expect("from_handoff");

    assert_eq!(app.session_id(), session.session_id());
    assert_eq!(app.server_pubkey(), pinned_key().to_bytes());
    assert!(app.is_alive());
    // Opened but not yet attested — the pending gate denies authorize.
    assert!(matches!(
        app.authorize(),
        Err(ClientError::NotAuthenticated)
    ));
}

#[tokio::test]
async fn handoff_wrong_process_id_fails() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let session = exchanged_session(&base_url).await;

    let (blob, key) = session
        .make_handoff(PROCESS_ID, Duration::seconds(60))
        .expect("make_handoff");
    // Recipient binding: the same key cannot open the blob under a
    // different process identity.
    let res = ClientSession::from_handoff(&key, &blob, "other.exe", Utc::now());
    assert!(matches!(
        res,
        Err(ClientError::Core(KeystoneError::InvalidMac))
    ));
}

#[tokio::test]
async fn handoff_wrong_key_fails() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let session = exchanged_session(&base_url).await;

    let (blob, _key) = session
        .make_handoff(PROCESS_ID, Duration::seconds(60))
        .expect("make_handoff");
    let res = ClientSession::from_handoff(&[0x99; 32], &blob, PROCESS_ID, Utc::now());
    assert!(matches!(
        res,
        Err(ClientError::Core(KeystoneError::InvalidMac))
    ));
}

#[tokio::test]
async fn handoff_expired_blob_fails() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let session = exchanged_session(&base_url).await;

    let (blob, key) = session
        .make_handoff(PROCESS_ID, Duration::seconds(30))
        .expect("make_handoff");
    let res =
        ClientSession::from_handoff(&key, &blob, PROCESS_ID, Utc::now() + Duration::seconds(31));
    assert!(matches!(
        res,
        Err(ClientError::Core(KeystoneError::Expired))
    ));
}

#[tokio::test]
async fn handoff_tampered_ciphertext_fails() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let session = exchanged_session(&base_url).await;

    let (mut blob, key) = session
        .make_handoff(PROCESS_ID, Duration::seconds(60))
        .expect("make_handoff");
    blob.ciphertext[0] ^= 1;
    let res = ClientSession::from_handoff(&key, &blob, PROCESS_ID, Utc::now());
    assert!(matches!(
        res,
        Err(ClientError::Core(KeystoneError::InvalidMac))
    ));
}

#[tokio::test]
async fn dead_session_cannot_handoff() {
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
    // The server verdict arrives via the next heartbeat and kills the
    // session — a dead session must not mint handoff material.
    let _ = client.heartbeat(&mut session).await;
    assert!(!session.is_alive());

    let res = session.make_handoff(PROCESS_ID, Duration::seconds(60));
    assert!(matches!(res, Err(ClientError::NotAuthenticated)));
}

#[tokio::test]
async fn handoff_session_attests_against_real_server() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let session = exchanged_session(&base_url).await;

    // Launcher seals; the "child process" opens with the delivered key.
    let (blob, key) = session
        .make_handoff(PROCESS_ID, Duration::seconds(60))
        .expect("make_handoff");
    let mut app = ClientSession::from_handoff(&key, &blob, PROCESS_ID, Utc::now())
        .expect("from_handoff");

    // The app builds its own client pinned to the key the blob carried
    // and performs its own attestation — never trusting the launcher's
    // word that the session is good.
    let app_client = KeystoneClient::new_insecure(
        &base_url,
        VerifyingKey::from_bytes(&app.server_pubkey()).unwrap(),
    )
    .unwrap();
    let lease = app_client
        .attest(&mut app, PROCESS_ID)
        .await
        .expect("attest");
    assert_eq!(lease.session_id, app.session_id());
    assert!(app.authorize().is_ok());

    // The attested session keeps working: heartbeat renews the lease.
    let renewed = app_client.heartbeat(&mut app).await.expect("heartbeat");
    assert_eq!(renewed.session_id, app.session_id());
}

#[tokio::test]
async fn handoff_session_gated_until_attest() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let session = exchanged_session(&base_url).await;

    let (blob, key) = session
        .make_handoff(PROCESS_ID, Duration::seconds(60))
        .expect("make_handoff");
    let mut app = ClientSession::from_handoff(&key, &blob, PROCESS_ID, Utc::now())
        .expect("from_handoff");
    let app_client = KeystoneClient::new_insecure(
        &base_url,
        VerifyingKey::from_bytes(&app.server_pubkey()).unwrap(),
    )
    .unwrap();

    // DESIGN step 6 is not skippable: before attest, authorize and
    // every session-bound call fail without touching the wire.
    assert!(matches!(
        app.authorize(),
        Err(ClientError::NotAuthenticated)
    ));
    let err = app_client
        .heartbeat(&mut app)
        .await
        .expect_err("heartbeat before attest must be refused locally");
    assert!(matches!(err, ClientError::NotAuthenticated));

    // Attest lifts the gate — the session authorizes and heartbeats.
    app_client
        .attest(&mut app, PROCESS_ID)
        .await
        .expect("attest");
    assert!(app.authorize().is_ok());
    app_client
        .heartbeat(&mut app)
        .await
        .expect("heartbeat after attest");
}

/// A handoff is a launch-time event, not a stored credential: asking
/// for an hour must clamp the sealed ttl to the 5-minute cap.
#[tokio::test]
async fn handoff_ttl_is_clamped_to_five_minutes() {
    let (base_url, _server) =
        spawn_server(test_state(Duration::seconds(300), Duration::seconds(60))).await;
    let session = exchanged_session(&base_url).await;

    let (blob, key) = session
        .make_handoff(PROCESS_ID, Duration::hours(1))
        .expect("make_handoff");
    assert!(
        blob.ttl <= Duration::minutes(5),
        "requested 1h, sealed ttl must be clamped: {:?}",
        blob.ttl
    );
    // The clamped blob still opens inside its real window and dies
    // right after it — the cap isn't decorative.
    ClientSession::from_handoff(&key, &blob, PROCESS_ID, Utc::now())
        .expect("clamped handoff must open");
    let res = ClientSession::from_handoff(
        &key,
        &blob,
        PROCESS_ID,
        Utc::now() + Duration::minutes(6),
    );
    assert!(matches!(
        res,
        Err(ClientError::Core(KeystoneError::Expired))
    ));
}
