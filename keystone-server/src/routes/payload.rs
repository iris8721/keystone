//! `POST /payload` (signed manifest plus wrapped artifact key) and
//! `GET /payload/{product}/{version}` (the sealed blob, streamed).
//!
//! The server never decrypts: the artifact key comes from the sealed
//! prefix, the plaintext hash and build id from the sidecars.

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use keystone_core::wire::{
    AUDIENCE_APP, DownloadAuthorization, ErrorCode, OP_PAYLOAD_FETCH, PayloadBody, PayloadRequest,
    mac_context, validate_build_id, validate_release,
};
use keystone_core::{
    ArtifactPaths, Envelope, MAX_ARTIFACT_BYTES, Manifest, SEALED_PREFIX_LEN, SignedManifest,
    artifact_context, artifact_key_from_prefix, payload_wrap_key, wrap_secret,
};
use sha2::Sha256;
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::audit::{AuditEvent, session_tag};
use crate::config::PayloadConfig;
use crate::downloads::PayloadRoute;
use crate::routes::common::{
    ApiError, Grant, Peer, SessionProof, WireJson, authorize_session, consume_nonce, live_grant,
    now_ms, sign,
};
use crate::state::AppState;
use crate::store::SessionRecord;

const TAG_LEN: u64 = 16;

pub(crate) async fn fetch(
    State(state): State<AppState>,
    peer: Peer,
    WireJson(req): WireJson<PayloadRequest>,
) -> Result<Json<Envelope>, ApiError> {
    req.validate().map_err(ApiError::bad_request)?;
    let context = mac_context::payload(&req.product, &req.version);
    let record = authorize_session(
        &state,
        &peer,
        SessionProof {
            route: "payload.fetch",
            per_session: state.inner.rate_limits.payload_fetch_per_session,
            session_id: &req.session_id,
            nonce: &req.nonce,
            issued_at: req.issued_at,
            mac: &req.mac,
            context: &context,
        },
    )
    .await?;
    let payloads = gate_release(&state, &record, &req.product)?;
    consume_nonce(&state, &req.session_id, &req.nonce, req.issued_at).await?;
    let grant = live_grant(&state, &record).await?;

    let mut release = open_release(payloads, &req.product, &req.version).await?;
    let mut prefix = [0u8; SEALED_PREFIX_LEN];
    release
        .file
        .read_exact(&mut prefix)
        .await
        .map_err(|e| artifact_invalid(format!("reading sealed prefix: {e}")))?;
    let artifact_key = artifact_key_from_prefix(
        &payloads.secret,
        &artifact_context(&req.product, &req.version, payloads.epoch),
        &prefix,
    );

    let now = now_ms();
    let expires_at = std::cmp::min(record.lease.expires_at, grant.expires_at);
    let manifest = SignedManifest::issue(
        &state.inner.issuer,
        Manifest {
            product: req.product.clone(),
            version: req.version.clone(),
            download_id: download_id(
                payloads,
                &record.account,
                &req.session_id,
                &release.build_id,
                &req.nonce,
                now,
            ),
            build_id: release.build_id.clone(),
            sha256: release.sha256,
            issued_at: now,
            expires_at,
        },
    );
    let wrap_key = payload_wrap_key(&record.session_key, &req.nonce);
    let body = PayloadBody {
        manifest,
        payload_key_wrap: wrap_secret(&wrap_key, &artifact_key),
        server_time: now,
        revoked_key_ids: state.revoked_key_ids(),
    };

    state.audit(AuditEvent::DownloadIssued {
        session_id: req.session_id,
        product: req.product.clone(),
        version: req.version.clone(),
    });
    if let Some(log) = &state.inner.downloads {
        log.record(
            PayloadRoute::ManifestIssued,
            &record.account,
            &req.product,
            &req.version,
            &release.build_id,
            &session_tag(&req.session_id),
        );
    }
    sign(
        &state,
        Grant {
            challenge: req.nonce,
            session_id: req.session_id,
            audience: AUDIENCE_APP,
            operation: OP_PAYLOAD_FETCH,
            issued_at: now,
            expires_at,
            body: &body,
        },
    )
}

pub(crate) async fn download(
    State(state): State<AppState>,
    peer: Peer,
    Path((product, version)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_release(&product, &version).map_err(ApiError::bad_request)?;
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| DownloadAuthorization::parse(v).ok())
        .ok_or_else(|| ApiError::new(ErrorCode::BadRequest, "invalid authorization header"))?;
    let context = mac_context::download(&product, &version);
    let record = authorize_session(
        &state,
        &peer,
        SessionProof {
            route: "payload.download",
            per_session: state.inner.rate_limits.payload_download_per_session,
            session_id: &auth.session_id,
            nonce: &auth.nonce,
            issued_at: auth.issued_at,
            mac: &auth.mac,
            context: &context,
        },
    )
    .await?;
    let payloads = gate_release(&state, &record, &product)?;
    consume_nonce(&state, &auth.session_id, &auth.nonce, auth.issued_at).await?;
    live_grant(&state, &record).await?;

    let release = open_release(payloads, &product, &version).await?;
    if let Some(log) = &state.inner.downloads {
        log.record(
            PayloadRoute::BlobServed,
            &record.account,
            &product,
            &version,
            &release.build_id,
            &session_tag(&auth.session_id),
        );
    }
    let mut response = Body::from_stream(ReaderStream::new(release.file)).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(release.len));
    Ok(response)
}

/// Product check before any backend or file work: a session serves only
/// its own product, whatever else the account holds.
fn gate_release<'a>(
    state: &'a AppState,
    record: &SessionRecord,
    product: &str,
) -> Result<&'a PayloadConfig, ApiError> {
    if record.product != product {
        return Err(ApiError::new(
            ErrorCode::WrongProduct,
            "product does not match the session",
        ));
    }
    state
        .inner
        .payloads
        .as_ref()
        .ok_or_else(|| ApiError::new(ErrorCode::BackendUnavailable, "payloads are not configured"))
}

struct Release {
    file: tokio::fs::File,
    len: u64,
    sha256: [u8; 32],
    build_id: String,
}

fn artifact_invalid(detail: impl std::fmt::Display) -> ApiError {
    tracing::error!(%detail, "artifact invalid");
    ApiError::new(ErrorCode::ArtifactInvalid, "artifact is unusable")
}

/// Open a sealed release and read its sidecars. A missing blob is 404
/// `artifact_not_found`; a missing or bad sidecar, or a blob outside the
/// size bounds, is 500 `artifact_invalid`.
async fn open_release(
    payloads: &PayloadConfig,
    product: &str,
    version: &str,
) -> Result<Release, ApiError> {
    let paths =
        ArtifactPaths::new(&payloads.dir, product, version).map_err(ApiError::bad_request)?;
    let file = match tokio::fs::File::open(&paths.sealed).await {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiError::new(
                ErrorCode::ArtifactNotFound,
                "no such release",
            ));
        }
        Err(e) => return Err(artifact_invalid(e)),
    };
    let len = file.metadata().await.map_err(artifact_invalid)?.len();
    if len > MAX_ARTIFACT_BYTES || len < SEALED_PREFIX_LEN as u64 + TAG_LEN {
        return Err(artifact_invalid(format!("sealed size {len} out of bounds")));
    }
    let sha_text = tokio::fs::read_to_string(&paths.sha256)
        .await
        .map_err(|e| artifact_invalid(format!(".sha256 sidecar: {e}")))?;
    let sha256: [u8; 32] = hex::decode(sha_text.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| artifact_invalid(".sha256 sidecar is not 64 hex characters"))?;
    let build_id = tokio::fs::read_to_string(&paths.build)
        .await
        .map_err(|e| artifact_invalid(format!(".build sidecar: {e}")))?
        .trim()
        .to_string();
    validate_build_id(&build_id).map_err(|e| artifact_invalid(format!(".build sidecar: {e}")))?;
    Ok(Release {
        file,
        len,
        sha256,
        build_id,
    })
}

/// Per-download watermark: HMAC(watermark secret, account, session, build,
/// request nonce, issue time), so a leaked manifest names the one request
/// that produced it.
fn download_id(
    payloads: &PayloadConfig,
    account: &str,
    session_id: &Uuid,
    build_id: &str,
    nonce: &[u8; 32],
    issued_at: DateTime<Utc>,
) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&payloads.watermark_secret[..])
        .expect("HMAC accepts any key length");
    mac.update(&(account.len() as u32).to_be_bytes());
    mac.update(account.as_bytes());
    mac.update(session_id.as_bytes());
    mac.update(&(build_id.len() as u32).to_be_bytes());
    mac.update(build_id.as_bytes());
    mac.update(nonce);
    mac.update(&issued_at.timestamp_millis().to_be_bytes());
    hex::encode(mac.finalize().into_bytes())
}
