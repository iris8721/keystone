//! The admin listener: `POST /revoke` and `PUT /artifacts/{product}/{version}`.
//!
//! Every admin request passes the certificate allow-list first (403 before
//! any bucket is touched), then the admin token; only failed token checks
//! are charged to the caller's address.

use std::path::{Path as FsPath, PathBuf};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Json;
use http_body_util::BodyExt;
use keystone_core::wire::{
    ADMIN_TOKEN_HEADER, BUILD_ID_HEADER, ErrorCode, PublishBody, RevokeBody, RevokeRequest,
    RevokeTarget, validate_build_id, validate_release,
};
use keystone_core::{ArtifactPaths, MAX_ARTIFACT_BYTES, artifact_context, fs, seal_artifact};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::AuditEvent;
use crate::config::PayloadConfig;
use crate::routes::common::{ApiError, Peer, WireJson, ip_key};
use crate::state::AppState;

pub(crate) async fn revoke(
    State(state): State<AppState>,
    peer: Peer,
    WireJson(req): WireJson<RevokeRequest>,
) -> Result<Json<RevokeBody>, ApiError> {
    require_admin_certificate(&state, &peer)?;
    req.validate().map_err(ApiError::bad_request)?;
    require_admin_token(&state, &peer, &req.admin_token).await?;
    let revoked = match &req.target {
        RevokeTarget::Session(id) => state.revoke_session(*id).await,
        RevokeTarget::Account(account) => state.revoke_account(account).await,
        RevokeTarget::KeyId(key_id) => state.revoke_key_id(*key_id).await,
    }
    .map_err(ApiError::from_server)?;
    Ok(Json(RevokeBody { revoked }))
}

/// Seal and store a new release. Releases are immutable: an existing
/// version is 409. The plaintext is streamed to an owner-only staging file
/// while hashing, sealed off the executor under the current epoch, and the
/// sidecars are written before the sealed blob, so readers never see a blob
/// without them.
pub(crate) async fn publish(
    State(state): State<AppState>,
    peer: Peer,
    Path((product, version)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<PublishBody>, ApiError> {
    require_admin_certificate(&state, &peer)?;
    let token = headers
        .get(ADMIN_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    require_admin_token(&state, &peer, token).await?;
    validate_release(&product, &version).map_err(ApiError::bad_request)?;
    let build_id = headers
        .get(BUILD_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::new(ErrorCode::BadRequest, "missing build id header"))?
        .to_string();
    validate_build_id(&build_id).map_err(ApiError::bad_request)?;
    let payloads = state.inner.payloads.as_ref().ok_or_else(|| {
        ApiError::new(ErrorCode::BackendUnavailable, "payloads are not configured")
    })?;
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > MAX_ARTIFACT_BYTES) {
        return Err(too_large());
    }

    let paths =
        ArtifactPaths::new(&payloads.dir, &product, &version).map_err(ApiError::bad_request)?;
    let product_dir = paths
        .sealed
        .parent()
        .map(FsPath::to_path_buf)
        .ok_or_else(|| ApiError::internal("artifact path has no parent"))?;
    let _serial = state.inner.publish.lock().await;
    if tokio::fs::try_exists(&paths.sealed)
        .await
        .map_err(ApiError::internal)?
    {
        return Err(ApiError::new(ErrorCode::Conflict, "release already exists"));
    }
    tokio::fs::create_dir_all(&product_dir)
        .await
        .map_err(ApiError::internal)?;

    let staging =
        Staging(product_dir.join(format!(".{version}.{}.upload", Uuid::new_v4().simple())));
    let sha256 = receive(body, &staging.0).await?;
    let sha_hex = hex::encode(sha256);
    seal_release(
        payloads, &product, &version, &build_id, &sha_hex, &staging.0, paths,
    )
    .await?;

    state.audit(AuditEvent::ArtifactPublished {
        product: product.clone(),
        version: version.clone(),
        build_id: build_id.clone(),
    });
    Ok(Json(PublishBody {
        product,
        version,
        sha256: sha_hex,
        build_id,
    }))
}

/// Removes the staging file however the request ends.
struct Staging(PathBuf);

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn too_large() -> ApiError {
    ApiError::new(ErrorCode::BadRequest, "artifact exceeds the size limit")
        .with_status(StatusCode::PAYLOAD_TOO_LARGE)
}

/// Stream the request body into `path` (owner-only), returning the sha256 of
/// what was written; more than `MAX_ARTIFACT_BYTES` is 413.
async fn receive(mut body: Body, path: &FsPath) -> Result<[u8; 32], ApiError> {
    let target = path.to_path_buf();
    let file = tokio::task::spawn_blocking(move || fs::open_append_owner_only(&target))
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|e| ApiError::new(ErrorCode::BadRequest, format!("reading body: {e}")))?;
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        received += chunk.len() as u64;
        if received > MAX_ARTIFACT_BYTES {
            return Err(too_large());
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(ApiError::internal)?;
    }
    file.sync_all().await.map_err(ApiError::internal)?;
    Ok(hasher.finalize().into())
}

/// Seal the staged plaintext and write `.sha256`, `.build`, then the blob.
async fn seal_release(
    payloads: &PayloadConfig,
    product: &str,
    version: &str,
    build_id: &str,
    sha_hex: &str,
    staged: &FsPath,
    paths: ArtifactPaths,
) -> Result<(), ApiError> {
    let secret = payloads.secret.clone();
    let context = artifact_context(product, version, payloads.epoch);
    let staged = staged.to_path_buf();
    let sha_hex = sha_hex.to_string();
    let build_id = build_id.to_string();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let plaintext = Zeroizing::new(std::fs::read(&staged)?);
        let sealed = seal_artifact(&secret, &context, &plaintext)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        fs::write_owner_only_atomic(&paths.sha256, sha_hex.as_bytes())?;
        fs::write_owner_only_atomic(&paths.build, build_id.as_bytes())?;
        fs::write_owner_only_atomic(&paths.sealed, &sealed)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)
}

/// When an allow-list is configured, the leaf certificate must be on it.
fn require_admin_certificate(state: &AppState, peer: &Peer) -> Result<(), ApiError> {
    let allowed = &state.inner.admin_certificates;
    if allowed.is_empty()
        || peer
            .cert_sha256()
            .is_some_and(|leaf| allowed.contains(&leaf))
    {
        Ok(())
    } else {
        Err(ApiError::new(ErrorCode::Forbidden, "forbidden"))
    }
}

/// Constant-time token check. Only failures are charged, so an operator
/// with the right token is never locked out by someone else's guesses.
async fn require_admin_token(
    state: &AppState,
    peer: &Peer,
    presented: &str,
) -> Result<(), ApiError> {
    let limiter = &state.inner.limiter;
    let key = ip_key("admin:failures", peer.ip);
    let per_window = state.inner.rate_limits.admin_failures_per_ip;
    if !limiter
        .peek(&key, per_window, state.inner.rate_limits.window)
        .await
    {
        return Err(ApiError::rate_limited());
    }
    let valid = state
        .inner
        .admin_token
        .as_ref()
        .is_some_and(|token| token.matches(presented));
    if valid {
        return Ok(());
    }
    limiter
        .check(&key, per_window, state.inner.rate_limits.window)
        .await;
    Err(ApiError::new(ErrorCode::Forbidden, "forbidden"))
}
