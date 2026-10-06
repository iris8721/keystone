//! HWID machine binding: the lock an exchange sets, the mismatch it
//! refuses, and the admin routes that reset and report it.

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use common::*;
use keystone_core::wire::{
    ADMIN_TOKEN_HEADER, AccountInfoBody, ErrorCode, ExchangeRequest, HwidResetBody,
    HwidResetRequest, PROTOCOL_HEADER, PROTOCOL_VERSION, paths,
};
use keystone_server::{AdminToken, AuditEvent};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MACHINE_A: [u8; 32] = [3; 32];
const MACHINE_B: [u8; 32] = [9; 32];

/// A harness over a machine-binding backend whose admin router accepts
/// [`ADMIN_TOKEN`].
async fn hwid_rig() -> (Harness, Router) {
    let source = TestSource::standard();
    source.bind_machines();
    let h = harness_with(source, |b| {
        b.admin_token(AdminToken::new(ADMIN_TOKEN).unwrap())
    })
    .await;
    let admin = h.admin_app();
    (h, admin)
}

fn from_machine(hwid: [u8; 32]) -> ExchangeRequest {
    ExchangeRequest {
        hwid,
        ..exchange_req(ACCOUNT, SECRET, PRODUCT)
    }
}

fn lock_of(hwid: [u8; 32]) -> [u8; 32] {
    Sha256::digest(hwid).into()
}

fn reset(token: &str, account: &str) -> HwidResetRequest {
    HwidResetRequest {
        admin_token: Zeroizing::new(token.to_string()),
        account: account.to_string(),
    }
}

/// `GET /accounts/{name}` with an optional admin token header.
async fn account_info(admin: &Router, name: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut req =
        Request::get(paths::account(name)).header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string());
    if let Some(token) = token {
        req = req.header(ADMIN_TOKEN_HEADER, token);
    }
    let (status, bytes) = send(admin, req.body(Body::empty()).unwrap()).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn the_first_exchange_binds_the_machine_and_the_same_one_returns() {
    let (h, _) = hwid_rig().await;
    assert_eq!(h.source.hwid_lock(ACCOUNT), None);

    let (first, _) = exchange_with(&h, from_machine(MACHINE_A)).await;
    assert_eq!(h.source.hwid_lock(ACCOUNT), Some(lock_of(MACHINE_A)));

    // The same machine logs in again, and the lock is unchanged.
    let (second, _) = exchange_with(&h, from_machine(MACHINE_A)).await;
    assert_ne!(first.id, second.id);
    assert_eq!(h.source.hwid_lock(ACCOUNT), Some(lock_of(MACHINE_A)));
    heartbeat_ok(&h, &second).await;
}

#[tokio::test]
async fn another_machine_is_refused_and_gets_no_session() {
    let (h, _) = hwid_rig().await;
    exchange_with(&h, from_machine(MACHINE_A)).await;

    let (status, body) = post(&h.app, "/exchange", &from_machine(MACHINE_B)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::HwidMismatch)
    );
    // The refusal neither rebinds the lock nor leaves a session behind.
    assert_eq!(h.source.hwid_lock(ACCOUNT), Some(lock_of(MACHINE_A)));
    assert_eq!(
        keystone_server::SessionStore::ids_for_account(h.store.as_ref(), ACCOUNT)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(h.audit.events().iter().any(|e| matches!(
        e,
        AuditEvent::ExchangeDenied {
            reason: ErrorCode::HwidMismatch,
            ..
        }
    )));
}

#[tokio::test]
async fn a_reset_clears_the_lock_and_the_next_exchange_rebinds() {
    let (h, admin) = hwid_rig().await;
    exchange_with(&h, from_machine(MACHINE_A)).await;

    let (status, body) = post(&admin, paths::HWID_RESET, &reset(ADMIN_TOKEN, ACCOUNT)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_value::<HwidResetBody>(body).unwrap(),
        HwidResetBody {
            account: ACCOUNT.to_string(),
            was_locked: true,
        }
    );
    assert_eq!(h.source.hwid_lock(ACCOUNT), None);
    assert!(
        h.audit
            .events()
            .iter()
            .any(|e| matches!(e, AuditEvent::HwidReset { account } if account == ACCOUNT))
    );

    let (session, _) = exchange_with(&h, from_machine(MACHINE_B)).await;
    assert_eq!(h.source.hwid_lock(ACCOUNT), Some(lock_of(MACHINE_B)));
    heartbeat_ok(&h, &session).await;

    // The machine that used to hold the lock is now the stranger.
    let (status, body) = post(&h.app, "/exchange", &from_machine(MACHINE_A)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::HwidMismatch)
    );
}

/// A reset that cleared a lock must not leave the old machine running:
/// heartbeats renew a lease without ever rechecking the lock, so a
/// surviving session would be a second concurrent machine.
#[tokio::test]
async fn a_reset_revokes_the_old_machines_sessions() {
    let (h, admin) = hwid_rig().await;
    let (old, _) = exchange_with(&h, from_machine(MACHINE_A)).await;
    heartbeat_ok(&h, &old).await;

    let (status, body) = post(&admin, paths::HWID_RESET, &reset(ADMIN_TOKEN, ACCOUNT)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        serde_json::from_value::<HwidResetBody>(body)
            .unwrap()
            .was_locked
    );

    // The old machine's lease is gone: its next heartbeat is refused.
    let (status, body) = heartbeat(&h, &old).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
    );
    assert!(
        h.audit
            .events()
            .iter()
            .any(|e| matches!(e, AuditEvent::AccountRevoked { account, .. } if account == ACCOUNT))
    );

    // A different machine binds and runs; the old one is now the stranger.
    let (new, _) = exchange_with(&h, from_machine(MACHINE_B)).await;
    assert_eq!(h.source.hwid_lock(ACCOUNT), Some(lock_of(MACHINE_B)));
    heartbeat_ok(&h, &new).await;
    let (status, body) = heartbeat(&h, &old).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
    );
}

#[tokio::test]
async fn resetting_an_unlocked_account_reports_no_lock() {
    let (h, admin) = hwid_rig().await;
    let (status, body) = post(&admin, paths::HWID_RESET, &reset(ADMIN_TOKEN, ACCOUNT)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !serde_json::from_value::<HwidResetBody>(body)
            .unwrap()
            .was_locked
    );
    assert_eq!(h.source.hwid_lock(ACCOUNT), None);
}

#[tokio::test]
async fn account_info_reports_the_lock_and_every_grant() {
    let source = TestSource::standard();
    source.bind_machines();
    source.set_grants(
        ACCOUNT,
        vec![
            grant(PRODUCT, Utc::now() + Duration::days(30), &["all"]),
            grant(OTHER_PRODUCT, Utc::now() - Duration::days(1), &[]),
        ],
    );
    let h = harness_with(source, |b| {
        b.admin_token(AdminToken::new(ADMIN_TOKEN).unwrap())
    })
    .await;
    let admin = h.admin_app();

    let (status, body) = account_info(&admin, ACCOUNT, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let info: AccountInfoBody = serde_json::from_value(body).unwrap();
    assert_eq!(info.name, ACCOUNT);
    assert!(!info.hwid_locked);
    // Expired grants are reported too: the operator sees the whole account.
    assert_eq!(
        info.entitlements
            .iter()
            .map(|g| g.product.as_str())
            .collect::<Vec<_>>(),
        [PRODUCT, OTHER_PRODUCT]
    );
    let expiries: Vec<_> = info.entitlements.iter().map(|g| g.expires_at).collect();
    assert!(expiries[0] > Utc::now() && expiries[1] < Utc::now());

    exchange_with(&h, from_machine(MACHINE_A)).await;
    let (status, body) = account_info(&admin, ACCOUNT, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        serde_json::from_value::<AccountInfoBody>(body)
            .unwrap()
            .hwid_locked
    );
}

#[tokio::test]
async fn unknown_accounts_are_not_found_on_both_routes() {
    let (_h, admin) = hwid_rig().await;
    let (status, body) = post(&admin, paths::HWID_RESET, &reset(ADMIN_TOKEN, "nobody")).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::NOT_FOUND, ErrorCode::BadRequest)
    );

    let (status, body) = account_info(&admin, "nobody", Some(ADMIN_TOKEN)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::NOT_FOUND, ErrorCode::BadRequest)
    );
}

#[tokio::test]
async fn both_admin_routes_need_the_admin_token() {
    let (h, admin) = hwid_rig().await;
    exchange_with(&h, from_machine(MACHINE_A)).await;
    let wrong = format!("{ADMIN_TOKEN}x");

    let (status, body) = post(&admin, paths::HWID_RESET, &reset(&wrong, ACCOUNT)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::Forbidden)
    );
    for token in [None, Some(wrong.as_str())] {
        let (status, body) = account_info(&admin, ACCOUNT, token).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::FORBIDDEN, ErrorCode::Forbidden)
        );
    }
    // The refused calls changed nothing.
    assert_eq!(h.source.hwid_lock(ACCOUNT), Some(lock_of(MACHINE_A)));

    // A server without an admin token refuses even the right one.
    let (bare, _) = (harness_with(TestSource::standard(), |b| b).await, ());
    let (status, body) = post(
        &bare.admin_app(),
        paths::HWID_RESET,
        &reset(ADMIN_TOKEN, ACCOUNT),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::Forbidden)
    );
}

#[tokio::test]
async fn the_admin_routes_are_not_on_the_public_router() {
    let (h, _) = hwid_rig().await;
    h.source.set_hwid_lock(ACCOUNT, Some(lock_of(MACHINE_A)));
    let (status, _) = post(&h.app, paths::HWID_RESET, &reset(ADMIN_TOKEN, ACCOUNT)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = account_info(&h.app, ACCOUNT, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(h.source.hwid_lock(ACCOUNT), Some(lock_of(MACHINE_A)));
}
