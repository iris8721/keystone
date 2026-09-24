//! Payload download: plaintext verified against the signed manifest, a
//! product mismatch refused without harming the session, and releases
//! published through the admin listener.

use std::path::{Path, PathBuf};

use crate::common::*;
use keystone_client::{ClientError, ErrorCode};
use keystone_core::{ArtifactPaths, SEALED_PREFIX_LEN, artifact_context, seal_artifact};
use keystone_server::PayloadConfig;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const VERSION: &str = "1.2.0";
const PAYLOAD_SECRET: [u8; 32] = [0x42; 32];
const EPOCH: u32 = 3;
const PLAINTEXT: &[u8] = b"the protected application bytes";

fn sealed(product: &str, version: &str, plaintext: &[u8]) -> Vec<u8> {
    seal_artifact(
        &PAYLOAD_SECRET,
        &artifact_context(product, version, EPOCH),
        plaintext,
    )
    .unwrap()
}

fn write_release(dir: &Path, product: &str, plaintext: &[u8]) -> ArtifactPaths {
    let paths = ArtifactPaths::new(dir, product, VERSION).unwrap();
    std::fs::create_dir_all(paths.sealed.parent().unwrap()).unwrap();
    std::fs::write(&paths.sealed, sealed(product, VERSION, plaintext)).unwrap();
    std::fs::write(&paths.sha256, hex::encode(Sha256::digest(plaintext))).unwrap();
    std::fs::write(&paths.build, format!("build-{product}-{VERSION}\n")).unwrap();
    paths
}

/// Removes the release directory when the test ends.
struct ReleaseDir(PathBuf);

impl Drop for ReleaseDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A rig serving releases of both products to an account entitled to both.
async fn payload_rig() -> (Rig, ReleaseDir) {
    let dir = std::env::temp_dir().join(format!("keystone-client-payload-{}", Uuid::new_v4()));
    write_release(&dir, PRODUCT, PLAINTEXT);
    write_release(&dir, OTHER_PRODUCT, b"other product bytes");
    let source = TestSource::with_grants(vec![
        grant(PRODUCT, &["all"]),
        grant(OTHER_PRODUCT, &["all"]),
    ]);
    let payloads = PayloadConfig::new(&dir, PAYLOAD_SECRET, EPOCH);
    let rig = Rig::start(source, SERVER_SANS, |b| b.payloads(payloads)).await;
    (rig, ReleaseDir(dir))
}

fn assert_invalid_response(result: Result<keystone_client::Payload, ClientError>) {
    match result {
        Err(ClientError::InvalidResponse(_)) => {}
        other => panic!("expected InvalidResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn download_returns_the_verified_plaintext() {
    let (rig, _dir) = payload_rig().await;
    let client = rig.client();
    let session = rig.exchange(&client).await;
    let payload = client
        .download_payload(&session, PRODUCT, VERSION)
        .await
        .expect("download");
    assert_eq!(payload.bytes, PLAINTEXT);
    assert_eq!(payload.manifest.manifest.product, PRODUCT);
    assert_eq!(payload.manifest.manifest.version, VERSION);
    assert_eq!(
        payload.manifest.manifest.sha256,
        <[u8; 32]>::from(Sha256::digest(PLAINTEXT))
    );
}

#[tokio::test]
async fn plaintext_not_matching_the_manifest_hash_is_rejected() {
    let (rig, dir) = payload_rig().await;
    // Decrypts cleanly under the release key, but is not the release.
    let paths = ArtifactPaths::new(&dir.0, PRODUCT, VERSION).unwrap();
    std::fs::write(
        &paths.sealed,
        sealed(PRODUCT, VERSION, b"substituted bytes"),
    )
    .unwrap();

    let client = rig.client();
    let session = rig.exchange(&client).await;
    assert_invalid_response(client.download_payload(&session, PRODUCT, VERSION).await);
    assert!(session.is_alive());
}

#[tokio::test]
async fn tampered_ciphertext_is_rejected() {
    let (rig, dir) = payload_rig().await;
    let paths = ArtifactPaths::new(&dir.0, PRODUCT, VERSION).unwrap();
    let mut blob = std::fs::read(&paths.sealed).unwrap();
    blob[SEALED_PREFIX_LEN + 3] ^= 0x01;
    std::fs::write(&paths.sealed, &blob).unwrap();

    let client = rig.client();
    let session = rig.exchange(&client).await;
    assert_invalid_response(client.download_payload(&session, PRODUCT, VERSION).await);
    assert!(session.is_alive());
}

#[tokio::test]
async fn other_product_is_wrong_product_and_the_session_survives() {
    let (rig, _dir) = payload_rig().await;
    let client = rig.client();
    let session = rig.exchange(&client).await;

    let err = client
        .download_payload(&session, OTHER_PRODUCT, VERSION)
        .await
        .unwrap_err();
    match err {
        ClientError::ServerRejected { status, code, .. } => {
            assert_eq!(status, 403);
            assert_eq!(code, Some(ErrorCode::WrongProduct));
        }
        other => panic!("expected wrong_product, got {other:?}"),
    }
    assert!(session.is_alive());

    let payload = client
        .download_payload(&session, PRODUCT, VERSION)
        .await
        .expect("own product still downloads");
    assert_eq!(payload.bytes, PLAINTEXT);
}

#[tokio::test]
async fn published_release_downloads_and_versions_are_immutable() {
    let (rig, _dir) = payload_rig().await;
    let admin = rig.admin();
    let bytes = b"freshly published release".to_vec();
    let published = admin
        .publish_artifact(PRODUCT, "2.0.0", "build-7", bytes.clone())
        .await
        .expect("publish");
    assert_eq!(published.product, PRODUCT);
    assert_eq!(published.version, "2.0.0");
    assert_eq!(published.build_id, "build-7");
    assert_eq!(published.sha256, hex::encode(Sha256::digest(&bytes)));

    let client = rig.client();
    let session = rig.exchange(&client).await;
    let payload = client
        .download_payload(&session, PRODUCT, "2.0.0")
        .await
        .expect("published release downloads");
    assert_eq!(payload.bytes, bytes);
    assert_eq!(payload.manifest.manifest.build_id, "build-7");

    let err = admin
        .publish_artifact(PRODUCT, "2.0.0", "build-8", b"replacement".to_vec())
        .await
        .unwrap_err();
    match err {
        ClientError::ServerRejected { status, code, .. } => {
            assert_eq!(status, 409);
            assert_eq!(code, Some(ErrorCode::Conflict));
        }
        other => panic!("expected a conflict, got {other:?}"),
    }

    // Invalid names never leave the client.
    let err = admin
        .publish_artifact("../etc", "2.0.0", "build-9", Vec::new())
        .await
        .unwrap_err();
    assert!(matches!(err, ClientError::Core(_)), "got {err:?}");
}
