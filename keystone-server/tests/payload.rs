//! Payload routes: session-product binding, the artifact layout and its
//! sidecars, tamper detection on the client side, and download records.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use common::*;
use keystone_core::wire::ErrorCode;
use keystone_core::{
    ArtifactPaths, SEALED_PREFIX_LEN, artifact_context, decrypt_artifact, seal_artifact,
    unwrap_artifact_key,
};
use keystone_server::PayloadConfig;
use sha2::{Digest, Sha256};

const VERSION: &str = "1.2.0";
const PAYLOAD_SECRET: [u8; 32] = [0x42; 32];
const EPOCH: u32 = 3;
const PLAINTEXT: &[u8] = b"the protected application bytes";

fn seal_release(dir: &Path, product: &str, version: &str, plaintext: &[u8]) -> ArtifactPaths {
    let paths = ArtifactPaths::new(dir, product, version).unwrap();
    std::fs::create_dir_all(paths.sealed.parent().unwrap()).unwrap();
    let context = artifact_context(product, version, EPOCH);
    std::fs::write(
        &paths.sealed,
        seal_artifact(&PAYLOAD_SECRET, &context, plaintext).unwrap(),
    )
    .unwrap();
    std::fs::write(&paths.sha256, hex::encode(Sha256::digest(plaintext))).unwrap();
    std::fs::write(&paths.build, format!("build-{product}-{version}\n")).unwrap();
    paths
}

fn both_products() -> Arc<TestSource> {
    let source = TestSource::standard();
    let until = Utc::now() + Duration::days(30);
    source.set_grants(
        ACCOUNT,
        vec![
            grant(PRODUCT, until, &["all"]),
            grant(OTHER_PRODUCT, until, &["all"]),
        ],
    );
    source
}

struct Rig {
    h: Harness,
    dir: PathBuf,
}

async fn rig_with_log(log: Option<PathBuf>) -> Rig {
    let dir = temp_dir("payload");
    seal_release(&dir, PRODUCT, VERSION, PLAINTEXT);
    seal_release(&dir, OTHER_PRODUCT, VERSION, b"other product bytes");
    let payloads = PayloadConfig::new(&dir, PAYLOAD_SECRET, EPOCH);
    let h = harness_with(both_products(), |b| {
        let b = b.payloads(payloads);
        match log {
            Some(path) => b.download_log(path),
            None => b,
        }
    })
    .await;
    Rig { h, dir }
}

async fn rig() -> Rig {
    rig_with_log(None).await
}

#[tokio::test]
async fn manifest_key_and_blob_round_trip() {
    let Rig { h, .. } = rig().await;
    let session = exchange(&h).await;
    let req = payload_req(&session, PRODUCT, VERSION);
    let (status, value) = post(&h.app, "/payload", &req).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let body = open_payload(&h.issuers, &value, &req);
    let manifest = body
        .manifest
        .verify(&h.issuers, Utc::now())
        .unwrap()
        .clone();
    assert_eq!(manifest.product, PRODUCT);
    assert_eq!(manifest.build_id, format!("build-{PRODUCT}-{VERSION}"));
    assert!(!manifest.download_id.is_empty());
    let key = unwrap_artifact_key(&session.key, &req.nonce, &body.payload_key_wrap).unwrap();

    let path = format!("/payload/{PRODUCT}/{VERSION}");
    let (status, sealed) = get(
        &h.app,
        &path,
        Some(&download_auth(&session, PRODUCT, VERSION)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let plaintext = decrypt_artifact(&key, &sealed).unwrap();
    assert_eq!(plaintext.as_slice(), PLAINTEXT);
    manifest.verify_payload(&plaintext).unwrap();
}

#[tokio::test]
async fn download_ids_differ_per_download() {
    let Rig { h, .. } = rig().await;
    let session = exchange(&h).await;
    let (first, second) = (
        payload_req(&session, PRODUCT, VERSION),
        payload_req(&session, PRODUCT, VERSION),
    );
    let ((_, a), (_, b)) = tokio::join!(
        post(&h.app, "/payload", &first),
        post(&h.app, "/payload", &second)
    );
    let a = open_payload(&h.issuers, &a, &first).manifest.manifest;
    let b = open_payload(&h.issuers, &b, &second).manifest.manifest;
    assert_ne!(a.download_id, b.download_id);
}

#[tokio::test]
async fn payload_body_carries_revocations_and_server_time() {
    let Rig { h, .. } = rig().await;
    h.state.revoke_key_id(9).await.unwrap();
    let session = exchange(&h).await;
    let req = payload_req(&session, PRODUCT, VERSION);
    let before = Utc::now() - Duration::seconds(1);
    let (status, value) = post(&h.app, "/payload", &req).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let body = open_payload(&h.issuers, &value, &req);
    assert_eq!(body.revoked_key_ids, vec![9]);
    assert!(body.server_time >= before && body.server_time <= Utc::now());
}

#[tokio::test]
async fn other_product_is_wrong_product_even_when_entitled() {
    let Rig { h, .. } = rig().await;
    let session = exchange(&h).await;
    let (status, body) = post(
        &h.app,
        "/payload",
        &payload_req(&session, OTHER_PRODUCT, VERSION),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::WrongProduct)
    );

    let path = format!("/payload/{OTHER_PRODUCT}/{VERSION}");
    let (status, bytes) = get(
        &h.app,
        &path,
        Some(&download_auth(&session, OTHER_PRODUCT, VERSION)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code_bytes(&bytes), ErrorCode::WrongProduct);
}

#[tokio::test]
async fn product_check_precedes_backend_and_file_work() {
    let Rig { h, dir } = rig().await;
    let session = exchange(&h).await;
    std::fs::remove_dir_all(dir.join(OTHER_PRODUCT)).unwrap();
    h.source.set_down(true);
    let (status, body) = post(
        &h.app,
        "/payload",
        &payload_req(&session, OTHER_PRODUCT, VERSION),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::WrongProduct)
    );

    let (status, body) = post(&h.app, "/payload", &payload_req(&session, PRODUCT, VERSION)).await;
    assert_eq!(
        (status, code(&body)),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::BackendUnavailable
        )
    );
}

#[tokio::test]
async fn missing_sidecars_are_artifact_invalid() {
    let Rig { h, dir } = rig().await;
    let session = exchange(&h).await;
    let paths = ArtifactPaths::new(&dir, PRODUCT, VERSION).unwrap();

    std::fs::remove_file(&paths.sha256).unwrap();
    let (status, body) = post(&h.app, "/payload", &payload_req(&session, PRODUCT, VERSION)).await;
    assert_eq!(
        (status, code(&body)),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::ArtifactInvalid
        )
    );

    seal_release(&dir, PRODUCT, VERSION, PLAINTEXT);
    std::fs::remove_file(&paths.build).unwrap();
    let (status, body) = post(&h.app, "/payload", &payload_req(&session, PRODUCT, VERSION)).await;
    assert_eq!(
        (status, code(&body)),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::ArtifactInvalid
        )
    );
    let path = format!("/payload/{PRODUCT}/{VERSION}");
    let (status, bytes) = get(
        &h.app,
        &path,
        Some(&download_auth(&session, PRODUCT, VERSION)),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(code_bytes(&bytes), ErrorCode::ArtifactInvalid);
}

#[tokio::test]
async fn flat_legacy_layout_is_not_served() {
    let dir = temp_dir("payload-legacy");
    let context = artifact_context(PRODUCT, VERSION, EPOCH);
    std::fs::write(
        dir.join(format!("{PRODUCT}-{VERSION}.bin")),
        seal_artifact(&PAYLOAD_SECRET, &context, PLAINTEXT).unwrap(),
    )
    .unwrap();
    let payloads = PayloadConfig::new(&dir, PAYLOAD_SECRET, EPOCH);
    let h = harness_with(TestSource::standard(), |b| b.payloads(payloads)).await;
    let session = exchange(&h).await;
    let (status, body) = post(&h.app, "/payload", &payload_req(&session, PRODUCT, VERSION)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::NOT_FOUND, ErrorCode::ArtifactNotFound)
    );
}

#[tokio::test]
async fn altered_artifact_is_caught_by_the_client() {
    let Rig { h, dir } = rig().await;
    let paths = ArtifactPaths::new(&dir, PRODUCT, VERSION).unwrap();
    let mut sealed = std::fs::read(&paths.sealed).unwrap();
    sealed[SEALED_PREFIX_LEN + 3] ^= 0x01;
    std::fs::write(&paths.sealed, &sealed).unwrap();

    let session = exchange(&h).await;
    let req = payload_req(&session, PRODUCT, VERSION);
    let (status, value) = post(&h.app, "/payload", &req).await;
    assert_eq!(status, StatusCode::OK, "the server never decrypts: {value}");
    let body = open_payload(&h.issuers, &value, &req);
    let key = unwrap_artifact_key(&session.key, &req.nonce, &body.payload_key_wrap).unwrap();
    let path = format!("/payload/{PRODUCT}/{VERSION}");
    let (status, served) = get(
        &h.app,
        &path,
        Some(&download_auth(&session, PRODUCT, VERSION)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(served, sealed);
    assert!(decrypt_artifact(&key, &served).is_err());
}

#[tokio::test]
async fn reused_payload_request_is_a_replay() {
    let Rig { h, .. } = rig().await;
    let session = exchange(&h).await;
    let req = payload_req(&session, PRODUCT, VERSION);
    assert_eq!(post(&h.app, "/payload", &req).await.0, StatusCode::OK);
    let (status, body) = post(&h.app, "/payload", &req).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::CONFLICT, ErrorCode::Replay)
    );

    let auth = download_auth(&session, PRODUCT, VERSION);
    let path = format!("/payload/{PRODUCT}/{VERSION}");
    assert_eq!(get(&h.app, &path, Some(&auth)).await.0, StatusCode::OK);
    let (status, bytes) = get(&h.app, &path, Some(&auth)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(code_bytes(&bytes), ErrorCode::Replay);
}

#[tokio::test]
async fn download_mac_is_bound_to_the_path() {
    let Rig { h, .. } = rig().await;
    let session = exchange(&h).await;
    let path = format!("/payload/{PRODUCT}/9.9.9");
    let (status, bytes) = get(
        &h.app,
        &path,
        Some(&download_auth(&session, PRODUCT, VERSION)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(code_bytes(&bytes), ErrorCode::InvalidMac);

    for bad in ["Bearer x", "Keystone nope", "Keystone a:b:c:d:e"] {
        let (status, bytes) = get(&h.app, &path, Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(code_bytes(&bytes), ErrorCode::BadRequest);
    }
}

#[tokio::test]
async fn unconfigured_payloads_are_backend_unavailable() {
    let h = harness().await;
    let session = exchange(&h).await;
    let (status, body) = post(&h.app, "/payload", &payload_req(&session, PRODUCT, VERSION)).await;
    assert_eq!(
        (status, code(&body)),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::BackendUnavailable
        )
    );
}

#[tokio::test]
async fn revoked_session_gets_no_payload() {
    let Rig { h, .. } = rig().await;
    let session = exchange(&h).await;
    h.state.revoke_session(session.id).await.unwrap();
    let (status, body) = post(&h.app, "/payload", &payload_req(&session, PRODUCT, VERSION)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
    );
}

#[tokio::test]
async fn downloads_are_logged_pseudonymously() {
    let log_dir = temp_dir("payload-log");
    let log = log_dir.join("downloads.jsonl");
    let Rig { h, .. } = rig_with_log(Some(log.clone())).await;
    let session = exchange(&h).await;
    let req = payload_req(&session, PRODUCT, VERSION);
    assert_eq!(post(&h.app, "/payload", &req).await.0, StatusCode::OK);
    let path = format!("/payload/{PRODUCT}/{VERSION}");
    let auth = download_auth(&session, PRODUCT, VERSION);
    assert_eq!(get(&h.app, &path, Some(&auth)).await.0, StatusCode::OK);

    let lines = wait_for_lines(&log, 2).await;
    let routes: Vec<_> = lines
        .iter()
        .map(|l| l["route"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(routes, ["manifest_issued", "blob_served"]);
    for line in &lines {
        assert_eq!(line["product"], PRODUCT);
        assert_eq!(line["build_id"], format!("build-{PRODUCT}-{VERSION}"));
        let pseudonym = line["account_pseudonym"].as_str().unwrap();
        assert_eq!(pseudonym.len(), 64);
        assert!(!pseudonym.contains(ACCOUNT));
    }
    assert!(
        !std::fs::read_to_string(&log)
            .unwrap()
            .contains(&session.id.to_string())
    );
}

async fn wait_for_lines(path: &Path, count: usize) -> Vec<serde_json::Value> {
    for _ in 0..100 {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        if lines.len() >= count {
            return lines;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("download log never reached {count} lines");
}
