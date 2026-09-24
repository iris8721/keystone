//! `PUT /artifacts/{product}/{version}` on the admin router: sealing,
//! immutability, size limit, token gating, and the served result.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use common::*;
use keystone_core::wire::{
    ADMIN_TOKEN_HEADER, BUILD_ID_HEADER, ErrorBody, ErrorCode, PROTOCOL_HEADER, PROTOCOL_VERSION,
    PublishBody, paths,
};
use keystone_core::{MAX_ARTIFACT_BYTES, decrypt_artifact, unwrap_artifact_key};
use keystone_server::{AdminToken, AuditEvent, PayloadConfig};
use sha2::{Digest, Sha256};

const VERSION: &str = "2.0.0";
const BUILD_ID: &str = "build-2026.09";
const PLAINTEXT: &[u8] = b"published application bytes";

async fn publish_rig(with_payloads: bool) -> (Harness, std::path::PathBuf) {
    let dir = temp_dir("publish");
    let payloads = PayloadConfig::new(&dir, [0x24; 32], 7);
    let h = harness_with(TestSource::standard(), |b| {
        let b = b.admin_token(AdminToken::new(ADMIN_TOKEN).unwrap());
        if with_payloads {
            b.payloads(payloads)
        } else {
            b
        }
    })
    .await;
    (h, dir)
}

fn put(token: &str, version: &str, body: Body) -> Request<Body> {
    Request::put(paths::artifact(PRODUCT, version))
        .header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string())
        .header(ADMIN_TOKEN_HEADER, token)
        .header(BUILD_ID_HEADER, BUILD_ID)
        .body(body)
        .unwrap()
}

async fn publish(h: &Harness, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    send(&h.admin_app(), request).await
}

fn error_code(bytes: &[u8]) -> ErrorCode {
    serde_json::from_slice::<ErrorBody>(bytes).unwrap().code
}

#[tokio::test]
async fn published_release_downloads_and_decrypts() {
    let (h, _) = publish_rig(true).await;
    let (status, bytes) = publish(&h, put(ADMIN_TOKEN, VERSION, Body::from(PLAINTEXT))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let body: PublishBody = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body.sha256, hex::encode(Sha256::digest(PLAINTEXT)));
    assert_eq!(
        (body.product.as_str(), body.version.as_str()),
        (PRODUCT, VERSION)
    );
    assert!(h.audit.events().contains(&AuditEvent::ArtifactPublished {
        product: PRODUCT.into(),
        version: VERSION.into(),
        build_id: BUILD_ID.into(),
    }));

    let session = exchange(&h).await;
    let req = payload_req(&session, PRODUCT, VERSION);
    let (status, value) = post(&h.app, "/payload", &req).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let payload = open_payload(&h.issuers, &value, &req);
    let manifest = payload
        .manifest
        .verify(&h.issuers, Utc::now())
        .unwrap()
        .clone();
    assert_eq!(manifest.build_id, BUILD_ID);
    let key = unwrap_artifact_key(&session.key, &req.nonce, &payload.payload_key_wrap).unwrap();
    let auth = download_auth(&session, PRODUCT, VERSION);
    let (status, sealed) = get(&h.app, &paths::download(PRODUCT, VERSION), Some(&auth)).await;
    assert_eq!(status, StatusCode::OK);
    let plaintext = decrypt_artifact(&key, &sealed).unwrap();
    assert_eq!(plaintext.as_slice(), PLAINTEXT);
    manifest.verify_payload(&plaintext).unwrap();
}

#[tokio::test]
async fn releases_are_immutable() {
    let (h, _) = publish_rig(true).await;
    let (status, _) = publish(&h, put(ADMIN_TOKEN, VERSION, Body::from(PLAINTEXT))).await;
    assert_eq!(status, StatusCode::OK);
    let (status, bytes) = publish(&h, put(ADMIN_TOKEN, VERSION, Body::from("replacement"))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error_code(&bytes), ErrorCode::Conflict);

    let session = exchange(&h).await;
    let req = payload_req(&session, PRODUCT, VERSION);
    let (_, value) = post(&h.app, "/payload", &req).await;
    let manifest = open_payload(&h.issuers, &value, &req).manifest.manifest;
    assert_eq!(manifest.sha256, <[u8; 32]>::from(Sha256::digest(PLAINTEXT)));
}

#[tokio::test]
async fn oversized_release_is_refused_and_leaves_nothing() {
    let (h, dir) = publish_rig(true).await;
    let mut request = put(ADMIN_TOKEN, VERSION, Body::from(PLAINTEXT));
    request
        .headers_mut()
        .insert("content-length", (MAX_ARTIFACT_BYTES + 1).into());
    let (status, bytes) = publish(&h, request).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error_code(&bytes), ErrorCode::BadRequest);
    assert!(!dir.join(PRODUCT).exists());
}

#[tokio::test]
async fn bad_token_is_forbidden() {
    let (h, dir) = publish_rig(true).await;
    for token in ["", "not-the-admin-token-but-long-enough-to-pass"] {
        let (status, bytes) = publish(&h, put(token, VERSION, Body::from(PLAINTEXT))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(error_code(&bytes), ErrorCode::Forbidden);
    }
    assert!(!dir.join(PRODUCT).exists());
}

#[tokio::test]
async fn invalid_release_names_and_build_ids_are_bad_requests() {
    let (h, _) = publish_rig(true).await;
    let (status, _) = publish(&h, put(ADMIN_TOKEN, "NUL", Body::from(PLAINTEXT))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut request = put(ADMIN_TOKEN, VERSION, Body::from(PLAINTEXT));
    request
        .headers_mut()
        .insert(BUILD_ID_HEADER, "has spaces".parse().unwrap());
    let (status, bytes) = publish(&h, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&bytes), ErrorCode::BadRequest);
}

#[tokio::test]
async fn publishing_without_payloads_is_unavailable() {
    let (h, _) = publish_rig(false).await;
    let (status, bytes) = publish(&h, put(ADMIN_TOKEN, VERSION, Body::from(PLAINTEXT))).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(&bytes), ErrorCode::BackendUnavailable);
}

#[tokio::test]
async fn publish_is_not_on_the_public_router() {
    let (h, _) = publish_rig(true).await;
    let (status, _) = send(&h.app, put(ADMIN_TOKEN, VERSION, Body::from(PLAINTEXT))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
