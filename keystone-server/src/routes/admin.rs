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
use keystone_core::{ArtifactPaths, MAX_PLAINTEXT_BYTES, artifact_context, fs, seal_artifact};
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
/// version is 409 `conflict`. The plaintext is streamed to an owner-only
/// staging file while hashing; sealing, the writes, and the audit record run
/// in a detached task that holds the publish lock, so a dropped request still
/// completes (or cleanly abandons) its release and never lets a second
/// publish of the same version interleave.
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
    let payloads = state.inner.payloads.clone().ok_or_else(|| {
        ApiError::new(ErrorCode::BackendUnavailable, "payloads are not configured")
    })?;
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > MAX_PLAINTEXT_BYTES) {
        return Err(too_large());
    }

    let paths =
        ArtifactPaths::new(&payloads.dir, &product, &version).map_err(ApiError::bad_request)?;
    let product_dir = paths
        .sealed
        .parent()
        .map(FsPath::to_path_buf)
        .ok_or_else(|| ApiError::internal("artifact path has no parent"))?;
    let serial = state.inner.publish.clone().lock_owned().await;
    if tokio::fs::try_exists(&paths.sealed)
        .await
        .map_err(ApiError::internal)?
    {
        return Err(conflict());
    }
    tokio::fs::create_dir_all(&product_dir)
        .await
        .map_err(ApiError::internal)?;

    let staging = |suffix: &str| {
        Staging(product_dir.join(format!(".{version}.{}.{suffix}", Uuid::new_v4().simple())))
    };
    let upload = staging("upload");
    let sealed_staging = staging("sealed");
    let sha256 = receive(body, &upload.0).await?;
    let release = Release {
        product,
        version,
        build_id,
        sha_hex: hex::encode(sha256),
    };

    let task = tokio::spawn(async move {
        let _serial = serial;
        let stored = seal_release(&payloads, &release, upload, sealed_staging, paths).await;
        if stored.is_ok() {
            state.audit(AuditEvent::ArtifactPublished {
                product: release.product.clone(),
                version: release.version.clone(),
                build_id: release.build_id.clone(),
            });
        }
        stored.map(|()| release)
    });
    let release = task.await.map_err(ApiError::internal)??;
    Ok(Json(PublishBody {
        product: release.product,
        version: release.version,
        sha256: release.sha_hex,
        build_id: release.build_id,
    }))
}

/// What a publish stores.
struct Release {
    product: String,
    version: String,
    build_id: String,
    sha_hex: String,
}

/// Removes a staging file however the request ends.
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

fn conflict() -> ApiError {
    ApiError::new(ErrorCode::Conflict, "release already exists")
}

/// Stream the request body into `path` (owner-only), returning the sha256 of
/// what was written; more than `MAX_PLAINTEXT_BYTES` is 413.
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
        if received > MAX_PLAINTEXT_BYTES {
            return Err(too_large());
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(ApiError::internal)?;
    }
    file.sync_all().await.map_err(ApiError::internal)?;
    Ok(hasher.finalize().into())
}

/// Seal the staged plaintext, then write `.sha256`, `.build`, and finally
/// link the blob into place. Sidecars are written only while no blob
/// exists, and the link never replaces one, so an existing release is never
/// altered.
async fn seal_release(
    payloads: &PayloadConfig,
    release: &Release,
    upload: Staging,
    sealed_staging: Staging,
    paths: ArtifactPaths,
) -> Result<(), ApiError> {
    let secret = payloads.secret.clone();
    let context = artifact_context(&release.product, &release.version, payloads.epoch);
    let sha_hex = release.sha_hex.clone();
    let build_id = release.build_id.clone();
    let placed = tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
        let plaintext = Zeroizing::new(std::fs::read(&upload.0)?);
        let sealed = seal_artifact(&secret, &context, &plaintext)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        fs::write_owner_only_atomic(&sealed_staging.0, &sealed)?;
        if paths.sealed.try_exists()? {
            return Ok(false);
        }
        fs::write_owner_only_atomic(&paths.sha256, sha_hex.as_bytes())?;
        fs::write_owner_only_atomic(&paths.build, build_id.as_bytes())?;
        match std::fs::hard_link(&sealed_staging.0, &paths.sealed) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e),
        }
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
    if placed { Ok(()) } else { Err(conflict()) }
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
