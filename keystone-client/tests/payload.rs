//! Client payload tests against the real server: manifest fetch,
//! sealed-blob download + decrypt + verify, and feature-grant
//! evaluation.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use chrono::{Duration, Utc};
use ed25519_dalek::VerifyingKey;
use keystone_client::{ClientError, KeystoneClient};
use keystone_core::{
    Entitlement, FeatureGrant, Issuer, KeystoneError, Manifest, SessionState, TrustedIssuers,
    artifact_context, decrypt_artifact, seal_artifact,
};
use keystone_server::entitlement::StubEntitlementSource;
use keystone_server::state::{ArtifactHashes, RateLimiter, RateLimits};
use keystone_server::{AppState, SessionStore, build_router};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use uuid::Uuid;

const ACCOUNT: &str = "dev";
const SECRET: &str = "devpass";
const PRODUCT: &str = "dev-product";
const VERSION: &str = "1.0.0";
const ISSUER_SEED: [u8; 32] = [7u8; 32];
const KEY_ID: u8 = 1;
const PAYLOAD_BYTES: &[u8] = b"keystone test payload blob";
const PAYLOAD_SECRET: [u8; 32] = [0x5Au8; 32];
/// The server's KEYSTONE_PAYLOAD_EPOCH for these tests; the sealed
/// fixture must be produced under the same one.
const PAYLOAD_EPOCH: u32 = 0;

fn test_state(payload_dir: Option<PathBuf>) -> AppState {
    let entitlements = Arc::new(StubEntitlementSource::new(vec![(
        ACCOUNT.to_string(),
        SECRET.to_string(),
        vec![Entitlement {
            account: ACCOUNT.to_string(),
            product: PRODUCT.to_string(),
            expires_at: Utc::now() + Duration::days(30),
            features: vec!["esp".to_string()],
        }],
    )]));
    AppState {
        issuer: Arc::new(Issuer::from_seed(&ISSUER_SEED, KEY_ID)),
        store: SessionStore::new(),
        entitlements,
        admin_token_hash: None,
        lease_ttl: Duration::seconds(300),
        grace_period: Duration::seconds(60),
        payload_dir,
        payload_secret: Some(PAYLOAD_SECRET),
        payload_epoch: PAYLOAD_EPOCH,
        downloads: None,
        watermark_secret: None,
        rate_limits: RateLimits::default(),
        rate_limiter: Arc::new(RateLimiter::default()),
        artifact_hashes: Arc::new(ArtifactHashes::default()),
        revoked_key_ids: Arc::new(RwLock::new(BTreeSet::new())),
    }
}

/// A payload dir holding the sealed release blob for product-version.
fn payload_dir_with(product: &str, version: &str, plaintext: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keystone-client-payload-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let context = artifact_context(product, version, PAYLOAD_EPOCH);
    let sealed = seal_artifact(&PAYLOAD_SECRET, &context, plaintext).unwrap();
    std::fs::write(dir.join(format!("{product}-{version}.bin")), sealed).unwrap();
    dir
}

async fn spawn_server(state: AppState) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });
    (format!("http://{addr}"), handle)
}

fn client_for(base_url: &str) -> KeystoneClient {
    KeystoneClient::new_insecure(base_url, issuers()).unwrap()
}

fn pinned_key() -> VerifyingKey {
    Issuer::from_seed(&ISSUER_SEED, KEY_ID).verifying_key()
}

fn issuers() -> TrustedIssuers {
    TrustedIssuers::single(KEY_ID, pinned_key())
}

#[tokio::test]
async fn fetch_and_download_payload() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let (base_url, _server) = spawn_server(test_state(Some(dir))).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .unwrap();

    let (signed, artifact_key) = client
        .fetch_manifest(&mut session, PRODUCT, VERSION)
        .await
        .expect("manifest fetch failed");
    // fetch_manifest already verified the signature — the returned
    // manifest must verify again under the baked issuer set.
    let manifest = signed.verify(&issuers(), Utc::now()).unwrap();
    assert_eq!(manifest.product, PRODUCT);
    assert_eq!(manifest.version, VERSION);
    assert_eq!(
        manifest.sha256,
        <[u8; 32]>::from(Sha256::digest(PAYLOAD_BYTES))
    );
    // The unwrapped key exists only because a live session produced it.
    assert_ne!(artifact_key, [0u8; 32]);

    let bytes = client
        .download_payload(&mut session, PRODUCT, VERSION)
        .await
        .expect("payload download failed");
    // The client gets verified plaintext — the sealed blob was
    // decrypted with the unwrapped key, then hash-checked.
    assert_eq!(bytes, PAYLOAD_BYTES);

    assert!(session.has_feature(manifest, "esp", Utc::now()));
    assert!(!session.has_feature(manifest, "aimbot", Utc::now()));
}

#[tokio::test]
async fn tampered_sealed_blob_fails_decrypt() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let (base_url, _server) = spawn_server(test_state(Some(dir.clone()))).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .unwrap();

    let (signed, artifact_key) = client
        .fetch_manifest(&mut session, PRODUCT, VERSION)
        .await
        .unwrap();

    // Flip a ciphertext byte in the sealed blob — the Poly1305 tag
    // must catch it before the manifest hash is even consulted.
    let mut sealed = std::fs::read(dir.join(format!("{PRODUCT}-{VERSION}.bin"))).unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 0xFF;
    let err = decrypt_artifact(&artifact_key, &sealed).unwrap_err();
    assert!(matches!(err, KeystoneError::InvalidMac));

    // And plaintext that decrypts under a different key still dies on
    // the manifest's attested sha256.
    let mut tampered = PAYLOAD_BYTES.to_vec();
    tampered[0] ^= 0xFF;
    let err = signed.manifest.verify_payload(&tampered).unwrap_err();
    assert!(matches!(err, KeystoneError::Malformed(_)));
}

#[tokio::test]
async fn missing_artifact_does_not_kill_session() {
    // Configured dir, no artifact inside — the miss is transient.
    let dir = std::env::temp_dir().join(format!("keystone-client-payload-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let (base_url, _server) = spawn_server(test_state(Some(dir))).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .unwrap();

    let err = client
        .fetch_manifest(&mut session, PRODUCT, VERSION)
        .await
        .unwrap_err();
    match err {
        ClientError::ServerRejected { status, .. } => assert_eq!(status, 404),
        other => panic!("expected 404 artifact_not_found, got {other}"),
    }
    // A missing artifact is not a verdict on the session — it stays
    // alive (in grace) rather than dying on a packaging gap.
    assert!(session.is_alive());
}

#[tokio::test]
async fn grace_state_session_fetch_is_transient() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let (base_url, _server) = spawn_server(state.clone()).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .unwrap();

    // Force the server-side record into Grace — the server answers
    // 403 session_not_active, which the client must read as transient.
    state
        .store
        .with_mut(&session.session_id(), |rec| {
            if let SessionState::Active { lease } = &rec.state {
                rec.state = SessionState::Grace {
                    lease: lease.clone(),
                    deadline: Utc::now() + Duration::seconds(30),
                };
            }
        })
        .expect("session must exist");

    let err = client
        .fetch_manifest(&mut session, PRODUCT, VERSION)
        .await
        .unwrap_err();
    match err {
        ClientError::ServerRejected { status, .. } => assert_eq!(status, 403),
        other => panic!("expected 403 session_not_active, got {other}"),
    }
    assert!(session.is_alive());
}

#[tokio::test]
async fn expired_feature_grant_is_inactive() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let (base_url, _server) = spawn_server(test_state(Some(dir))).await;
    let client = client_for(&base_url);
    let session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .unwrap();
    let now = Utc::now();
    let manifest = Manifest {
        product: PRODUCT.to_string(),
        version: VERSION.to_string(),
        build_id: "test-build".to_string(),
        download_id: String::new(),
        sha256: [0u8; 32],
        feature_grants: vec![
            FeatureGrant {
                feature: "esp".to_string(),
                expires_at: now - Duration::seconds(1),
            },
            FeatureGrant {
                feature: "aimbot".to_string(),
                expires_at: now + Duration::hours(1),
            },
        ],
        issued_at: now,
        expires_at: now + Duration::minutes(5),
    };
    // An expired grant is indistinguishable from an absent one.
    assert!(!session.has_feature(&manifest, "esp", now));
    assert!(session.has_feature(&manifest, "aimbot", now));
    assert!(!session.has_feature(&manifest, "fly", now));

    // Past the manifest's own expiry every grant is dead — a stale
    // manifest can't keep features alive.
    let later = now + Duration::minutes(10);
    assert!(!session.has_feature(&manifest, "aimbot", later));
}

#[tokio::test]
async fn payload_fetch_after_revoke_kills_session() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    let state = test_state(Some(dir));
    let (base_url, _server) = spawn_server(state.clone()).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .unwrap();

    assert!(state.store.revoke(&session.session_id()));
    let err = client
        .fetch_manifest(&mut session, PRODUCT, VERSION)
        .await
        .unwrap_err();
    match err {
        ClientError::ServerRejected { status, .. } => assert_eq!(status, 403),
        other => panic!("expected 403 rejection, got {other}"),
    }
    // An explicit denial is a verdict — the session is dead, not in
    // grace.
    assert!(!session.is_alive());
}

/// A served blob whose plaintext doesn't match the manifest's attested
/// sha256 must error with NO bytes returned — verify-before-return is
/// the whole contract. The mismatch is staged via a `.sha256` sidecar
/// attesting a different hash than the sealed plaintext.
#[tokio::test]
async fn download_payload_hash_mismatch_returns_no_bytes() {
    let dir = payload_dir_with(PRODUCT, VERSION, PAYLOAD_BYTES);
    // The sidecar lies: it attests the hash of different bytes, so the
    // manifest signs a sha256 the real plaintext can never match.
    std::fs::write(
        dir.join(format!("{PRODUCT}-{VERSION}.sha256")),
        hex::encode(Sha256::digest(b"attacker bytes")),
    )
    .unwrap();
    let (base_url, _server) = spawn_server(test_state(Some(dir))).await;
    let client = client_for(&base_url);
    let mut session = client
        .exchange(ACCOUNT, SECRET, PRODUCT, [9u8; 32])
        .await
        .unwrap();

    let err = client
        .download_payload(&mut session, PRODUCT, VERSION)
        .await
        .expect_err("a hash-mismatched payload must not return bytes");
    assert!(
        matches!(err, ClientError::Core(KeystoneError::Malformed(_))),
        "expected a hash-mismatch error, got {err:?}"
    );
    // A corrupt artifact is a packaging failure, not a verdict — the
    // session stays alive.
    assert!(session.is_alive());
}
