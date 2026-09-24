//! The public and admin routers.
//!
//! Every request must carry `keystone-protocol: 2`; JSON bodies are capped
//! at 16 KiB; every denial is a `wire::ErrorBody`.

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use keystone_core::wire::{ErrorCode, PROTOCOL_HEADER, PROTOCOL_VERSION, paths};

use crate::state::AppState;

mod admin;
mod attest;
mod common;
mod exchange;
mod handoff;
mod heartbeat;
mod payload;

use common::ApiError;

/// Largest accepted JSON request body.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// Client-facing routes: `/exchange`, `/handoff`, `/attest`, `/heartbeat`,
/// `POST /payload`, `GET /payload/{product}/{version}`.
///
/// [`crate::serve()`] provides what the routes need from the connection.
/// Embedders serving the router themselves must use
/// `into_make_service_with_connect_info::<SocketAddr>()`, and under mTLS
/// accept connections through [`crate::tls::PeerCertAcceptor`]. A request
/// without the client address, or without client certificates when the
/// state requires them, is refused with 500 `unknown`.
pub fn public_router(state: AppState) -> Router {
    Router::new()
        .route(paths::EXCHANGE, post(exchange::exchange))
        .route(paths::HANDOFF, post(handoff::handoff))
        .route(paths::ATTEST, post(attest::attest))
        .route(paths::HEARTBEAT, post(heartbeat::heartbeat))
        .route(paths::PAYLOAD, post(payload::fetch))
        .route(
            &paths::download(":product", ":version"),
            get(payload::download),
        )
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(require_protocol))
        .with_state(state)
}

/// Operator routes: `POST /revoke` and `PUT /artifacts/{product}/{version}`
/// (plaintext body up to `MAX_ARTIFACT_BYTES`). Serve only on the admin
/// listener, with the same connection requirements as [`public_router`].
pub fn admin_router(state: AppState) -> Router {
    Router::new()
        .route(paths::REVOKE, post(admin::revoke))
        .route(
            &paths::artifact(":product", ":version"),
            put(admin::publish),
        )
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(require_protocol))
        .with_state(state)
}

async fn require_protocol(req: Request, next: Next) -> Response {
    let supported = req
        .headers()
        .get(PROTOCOL_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u16>().ok())
        == Some(PROTOCOL_VERSION);
    if supported {
        next.run(req).await
    } else {
        ApiError::new(
            ErrorCode::UnsupportedProtocol,
            format!("{PROTOCOL_HEADER}: {PROTOCOL_VERSION} required"),
        )
        .into_response()
    }
}

async fn not_found() -> ApiError {
    ApiError::new(ErrorCode::BadRequest, "no such route").with_status(StatusCode::NOT_FOUND)
}
