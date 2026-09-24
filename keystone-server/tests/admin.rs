//! The admin router and key revocation: token gating, failure charging, the
//! active-key guard, persist-before-apply, and builder validation.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use chrono::Duration;
use common::*;
use keystone_core::Issuer;
use keystone_core::wire::{ErrorCode, RevokeBody, RevokeRequest, RevokeTarget};
use keystone_server::{
    AdminToken, AppState, AppStateBuilder, FileRevocationStore, MemoryRevocations, RateLimits,
    RevocationStore, ServerError, admin_router,
};
use zeroize::Zeroizing;

fn revoke(token: &str, target: RevokeTarget) -> RevokeRequest {
    RevokeRequest {
        admin_token: Zeroizing::new(token.to_string()),
        target,
    }
}

async fn admin_rig(revocations: Arc<dyn RevocationStore>) -> (Harness, Router) {
    let h = harness_with(TestSource::standard(), |b| {
        b.admin_token(AdminToken::new(ADMIN_TOKEN).unwrap())
            .revocations(revocations)
    })
    .await;
    let admin = h.admin_app();
    (h, admin)
}

#[tokio::test]
async fn revoke_needs_the_admin_token() {
    let (h, admin) = admin_rig(Arc::new(MemoryRevocations::new())).await;
    let session = exchange(&h).await;
    let wrong = format!("{ADMIN_TOKEN}x");
    let (status, body) = post(
        &admin,
        "/revoke",
        &revoke(&wrong, RevokeTarget::Session(session.id)),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::Forbidden)
    );
    heartbeat_ok(&h, &session).await;

    let (status, body) = post(
        &admin,
        "/revoke",
        &revoke(ADMIN_TOKEN, RevokeTarget::Session(session.id)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body: RevokeBody = serde_json::from_value(body).unwrap();
    assert_eq!(body.revoked, 1);
    let (status, body) = heartbeat(&h, &session).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
    );
}

#[tokio::test]
async fn admin_router_without_a_token_refuses_everyone() {
    let h = harness().await;
    let (status, body) = post(
        &h.admin_app(),
        "/revoke",
        &revoke(ADMIN_TOKEN, RevokeTarget::KeyId(9)),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::Forbidden)
    );
}

#[tokio::test]
async fn only_failed_admin_tokens_are_charged() {
    let limits = RateLimits {
        admin_failures_per_ip: 2,
        ..RateLimits::default()
    };
    let h = harness_with(TestSource::standard(), |b| {
        b.admin_token(AdminToken::new(ADMIN_TOKEN).unwrap())
            .rate_limits(limits)
    })
    .await;
    let admin = h.admin_app();
    for _ in 0..5 {
        let target = RevokeTarget::Account("nobody".into());
        let (status, _) = post(&admin, "/revoke", &revoke(ADMIN_TOKEN, target)).await;
        assert_eq!(status, StatusCode::OK);
    }
    let wrong = format!("{ADMIN_TOKEN}x");
    for _ in 0..2 {
        let (status, body) = post(&admin, "/revoke", &revoke(&wrong, RevokeTarget::KeyId(9))).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::FORBIDDEN, ErrorCode::Forbidden)
        );
    }
    let (status, body) = post(&admin, "/revoke", &revoke(&wrong, RevokeTarget::KeyId(9))).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
    );

    let elsewhere = with_peer(admin_router(h.state.clone()), "192.0.2.99:1");
    let target = RevokeTarget::Account("nobody".into());
    let (status, _) = post(&elsewhere, "/revoke", &revoke(ADMIN_TOKEN, target)).await;
    assert_eq!(status, StatusCode::OK);
}

async fn builder_error(configure: fn(AppStateBuilder) -> AppStateBuilder) -> &'static str {
    let builder = AppState::builder(Issuer::generate(1), TestSource::standard());
    match configure(builder).build().await {
        Err(ServerError::Config { var, .. }) => var,
        Err(other) => panic!("unexpected {other}"),
        Ok(_) => panic!("built"),
    }
}

#[tokio::test]
async fn builder_errors_name_the_builder_setting() {
    assert_eq!(
        builder_error(|b| b.lease_ttl(Duration::zero())).await,
        "lease_ttl"
    );
    assert_eq!(
        builder_error(|b| b.grace_period(Duration::seconds(-1))).await,
        "grace_period"
    );
    assert_eq!(
        builder_error(|b| {
            b.rate_limits(RateLimits {
                window: std::time::Duration::ZERO,
                ..RateLimits::default()
            })
        })
        .await,
        "rate_limits"
    );
    assert_eq!(
        builder_error(|b| b.download_log("downloads.jsonl".into())).await,
        "download_log"
    );
    assert_eq!(
        builder_error(|b| {
            b.admin_token(AdminToken::new(ADMIN_TOKEN).unwrap())
                .require_client_certificates(true)
        })
        .await,
        "admin_certificates"
    );
}

#[tokio::test]
async fn empty_revocations_file_is_an_empty_set() {
    let path = temp_dir("revocations").join("revoked-keys.json");
    std::fs::write(&path, b"").unwrap();
    let store = FileRevocationStore::new(path);
    assert!(store.load().await.unwrap().is_empty());
    store.persist(4).await.unwrap();
    assert_eq!(store.load().await.unwrap(), BTreeSet::from([4]));
}

#[tokio::test]
async fn the_active_signing_key_cannot_be_revoked() {
    let revocations = Arc::new(MemoryRevocations::new());
    let (h, admin) = admin_rig(revocations.clone()).await;
    let session = exchange(&h).await;
    let (status, body) = post(
        &admin,
        "/revoke",
        &revoke(ADMIN_TOKEN, RevokeTarget::KeyId(1)),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::CONFLICT, ErrorCode::ActiveSigningKey)
    );
    assert!(revocations.load().await.unwrap().is_empty());
    assert!(h.state.revoked_key_ids().is_empty());
    heartbeat_ok(&h, &session).await;
    assert!(matches!(
        h.state.revoke_key_id(1).await,
        Err(ServerError::ActiveKeyRevoked(1))
    ));
}

#[tokio::test]
async fn key_revocation_is_persisted_published_and_kills_sessions() {
    let revocations = Arc::new(MemoryRevocations::new());
    let (h, admin) = admin_rig(revocations.clone()).await;
    let a = exchange(&h).await;
    let b = exchange(&h).await;
    let (status, body) = post(
        &admin,
        "/revoke",
        &revoke(ADMIN_TOKEN, RevokeTarget::KeyId(7)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_value::<RevokeBody>(body).unwrap().revoked,
        2
    );
    assert_eq!(revocations.load().await.unwrap(), BTreeSet::from([7]));
    for session in [&a, &b] {
        let (status, body) = heartbeat(&h, session).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
        );
    }
    let (_, fresh) = exchange_with(&h, exchange_req(ACCOUNT, SECRET, PRODUCT)).await;
    assert_eq!(fresh.revoked_key_ids, vec![7]);
}

#[tokio::test]
async fn failed_persist_applies_nothing() {
    let unwritable = temp_dir("revocations")
        .join("missing-dir")
        .join("revoked.json");
    let (h, admin) = admin_rig(Arc::new(FileRevocationStore::new(unwritable))).await;
    let session = exchange(&h).await;
    let (status, body) = post(
        &admin,
        "/revoke",
        &revoke(ADMIN_TOKEN, RevokeTarget::KeyId(7)),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::BackendUnavailable
        )
    );
    assert!(h.state.revoked_key_ids().is_empty());
    heartbeat_ok(&h, &session).await;
}

#[tokio::test]
async fn file_revocations_survive_a_restart() {
    let path = temp_dir("revocations").join("revoked-keys.json");
    let (h, admin) = admin_rig(Arc::new(FileRevocationStore::new(path.clone()))).await;
    for key_id in [5, 6] {
        let (status, _) = post(
            &admin,
            "/revoke",
            &revoke(ADMIN_TOKEN, RevokeTarget::KeyId(key_id)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(serde_json::from_str::<Vec<u8>>(&text).unwrap(), vec![5, 6]);
    drop(h);

    let restarted = AppState::builder(Issuer::generate(1), TestSource::standard())
        .revocations(Arc::new(FileRevocationStore::new(path.clone())))
        .build()
        .await
        .unwrap();
    assert_eq!(restarted.revoked_key_ids(), vec![5, 6]);

    let refused = AppState::builder(Issuer::generate(6), TestSource::standard())
        .revocations(Arc::new(FileRevocationStore::new(path)))
        .build()
        .await;
    assert!(matches!(refused, Err(ServerError::ActiveKeyRevoked(6))));
}

#[tokio::test]
async fn startup_refuses_a_revoked_active_key() {
    let refused = AppState::builder(Issuer::generate(2), TestSource::standard())
        .revoked_key_ids(BTreeSet::from([2]))
        .build()
        .await;
    assert!(matches!(refused, Err(ServerError::ActiveKeyRevoked(2))));
}

#[tokio::test]
async fn account_revocation_counts_live_sessions() {
    let (h, admin) = admin_rig(Arc::new(MemoryRevocations::new())).await;
    let a = exchange(&h).await;
    exchange(&h).await;
    h.state.revoke_session(a.id).await.unwrap();
    let target = RevokeTarget::Account(ACCOUNT.to_string());
    let (status, body) = post(&admin, "/revoke", &revoke(ADMIN_TOKEN, target)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_value::<RevokeBody>(body).unwrap().revoked,
        1
    );
}
