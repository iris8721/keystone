//! Handoff v2: single-use handoffs minted by a live session and redeemed
//! for independent child sessions.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use common::*;
use keystone_core::DeadReason;
use keystone_core::wire::{ErrorCode, MAX_HANDOFF_TTL};
use keystone_server::{MemoryRevocations, RateLimits};

#[tokio::test]
async fn attest_creates_a_child_session_of_its_own() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
    let (child, body) = attest_ok(&h.app, &h.issuers, &parent.id, &handoff).await;
    assert_ne!(child.id, parent.id);
    assert_ne!(child.key, parent.key);
    assert_eq!(body.features[0].feature, "all");

    let lease = heartbeat_ok(&h, &child).await;
    assert_eq!(lease.lease.session_id, child.id);
    let (record, _) = h.store_record(child.id).await;
    assert_eq!(record.parent, Some(parent.id));
    assert_eq!(record.product, PRODUCT);
    assert_eq!(record.account, ACCOUNT);
    heartbeat_ok(&h, &parent).await;
}

#[tokio::test]
async fn a_handoff_redeems_exactly_once() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
    attest_ok(&h.app, &h.issuers, &parent.id, &handoff).await;
    let (status, body) = post(
        &h.app,
        "/attest",
        &attest_req(&parent.id, &handoff, PROCESS_ID),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(code(&body), ErrorCode::HandoffInvalid);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_redemptions_have_exactly_one_winner() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let app = h.app.clone();
            let req = attest_req(&parent.id, &handoff, PROCESS_ID);
            tokio::spawn(async move { post(&app, "/attest", &req).await })
        })
        .collect();
    let mut ok = 0;
    for task in tasks {
        let (status, body) = task.await.unwrap();
        if status == StatusCode::OK {
            ok += 1;
        } else {
            assert_eq!(code(&body), ErrorCode::HandoffInvalid);
        }
    }
    assert_eq!(ok, 1);
}

#[tokio::test]
async fn attest_rejects_anything_but_the_minted_binding() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let other = exchange(&h).await;

    let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
    let wrong_process = attest_req(&parent.id, &handoff, "other.exe");
    let (status, body) = post(&h.app, "/attest", &wrong_process).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::HandoffInvalid)
    );

    let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
    let wrong_secret = attest_req_with(&parent.id, &handoff.handoff_id, &[0u8; 32], PROCESS_ID);
    let (status, body) = post(&h.app, "/attest", &wrong_secret).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::HandoffInvalid)
    );

    let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
    let wrong_parent = attest_req(&other.id, &handoff, PROCESS_ID);
    let (status, body) = post(&h.app, "/attest", &wrong_parent).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::HandoffInvalid)
    );

    let unknown = attest_req_with(&parent.id, &nonce(), &nonce(), PROCESS_ID);
    let (status, body) = post(&h.app, "/attest", &unknown).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::HandoffInvalid)
    );
}

#[tokio::test]
async fn expired_handoff_cannot_be_redeemed() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let req = handoff_req(&parent, PROCESS_ID, 1);
    let (status, value) = post(&h.app, "/handoff", &req).await;
    assert_eq!(status, StatusCode::OK);
    // The envelope itself expires with the 1 ms handoff, so read the body raw.
    let env: keystone_core::Envelope = serde_json::from_value(value).unwrap();
    let handoff: keystone_core::wire::HandoffBody = serde_json::from_slice(&env.body).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let (status, body) = post(
        &h.app,
        "/attest",
        &attest_req(&parent.id, &handoff, PROCESS_ID),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::HandoffInvalid)
    );
}

#[tokio::test]
async fn handoff_lifetime_is_clamped() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let req = handoff_req(&parent, PROCESS_ID, u64::MAX);
    let before = Utc::now();
    let (status, value) = post(&h.app, "/handoff", &req).await;
    assert_eq!(status, StatusCode::OK);
    let env: keystone_core::Envelope = serde_json::from_value(value).unwrap();
    let body: keystone_core::wire::HandoffBody = serde_json::from_slice(&env.body).unwrap();
    assert!(body.expires_at <= before + MAX_HANDOFF_TTL + Duration::seconds(1));
    assert_eq!(env.expires_at, body.expires_at);
}

#[tokio::test]
async fn at_most_four_handoffs_are_outstanding() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let mut minted = Vec::new();
    for _ in 0..4 {
        minted.push(handoff_ok(&h.app, &h.issuers, &parent).await);
    }
    let (status, body) = post(
        &h.app,
        "/handoff",
        &handoff_req(&parent, PROCESS_ID, 60_000),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(code(&body), ErrorCode::RateLimited);

    attest_ok(&h.app, &h.issuers, &parent.id, &minted[0]).await;
    handoff_ok(&h.app, &h.issuers, &parent).await;
}

#[tokio::test]
async fn handoff_request_is_mac_bound_and_single_use() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let mut req = handoff_req(&parent, PROCESS_ID, 60_000);
    req.ttl_millis = 120_000;
    let (status, body) = post(&h.app, "/handoff", &req).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::UNAUTHORIZED, ErrorCode::InvalidMac)
    );

    let req = handoff_req(&parent, PROCESS_ID, 60_000);
    assert_eq!(post(&h.app, "/handoff", &req).await.0, StatusCode::OK);
    let (status, body) = post(&h.app, "/handoff", &req).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::CONFLICT, ErrorCode::Replay)
    );
}

#[tokio::test]
async fn child_outlives_the_parent_lease() {
    let h = harness_with(TestSource::standard(), |b| {
        b.lease_ttl(Duration::seconds(2))
    })
    .await;
    let (parent, body) = exchange_with(&h, exchange_req(ACCOUNT, SECRET, PRODUCT)).await;
    let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
    let (child, _) = attest_ok(&h.app, &h.issuers, &parent.id, &handoff).await;
    // Renew only the child, well inside its lease, until the parent's lapses.
    let parent_gone = body.lease.expires_at + Duration::milliseconds(100);
    while Utc::now() < parent_gone {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        heartbeat_ok(&h, &child).await;
    }
    let (status, body) = heartbeat(&h, &parent).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::GONE, ErrorCode::SessionExpired)
    );
    heartbeat_ok(&h, &child).await;
}

#[tokio::test]
async fn attest_on_a_lapsed_parent_lease_expires_the_parent() {
    let h = harness_with(TestSource::standard(), |b| {
        b.lease_ttl(Duration::seconds(1))
    })
    .await;
    let (parent, body) = exchange_with(&h, exchange_req(ACCOUNT, SECRET, PRODUCT)).await;
    let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
    let lapsed = (body.lease.expires_at - Utc::now() + Duration::milliseconds(100))
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(lapsed).await;

    let (status, body) = post(
        &h.app,
        "/attest",
        &attest_req(&parent.id, &handoff, PROCESS_ID),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::HandoffInvalid)
    );
    assert_eq!(
        h.store_record(parent.id).await.0.dead,
        Some(DeadReason::Expired)
    );
}

#[tokio::test]
async fn full_parent_bucket_leaves_the_handoff_redeemable() {
    let limits = RateLimits {
        attest_per_session: 1,
        window: std::time::Duration::from_secs(1),
        ..RateLimits::default()
    };
    let h = harness_with(TestSource::standard(), |b| b.rate_limits(limits)).await;
    let parent = exchange(&h).await;
    let first = handoff_ok(&h.app, &h.issuers, &parent).await;
    let second = handoff_ok(&h.app, &h.issuers, &parent).await;
    attest_ok(&h.app, &h.issuers, &parent.id, &first).await;

    let (status, body) = post(
        &h.app,
        "/attest",
        &attest_req(&parent.id, &second, PROCESS_ID),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
    );
    tokio::time::sleep(limits.window + std::time::Duration::from_millis(100)).await;
    attest_ok(&h.app, &h.issuers, &parent.id, &second).await;
}

#[tokio::test]
async fn failed_attest_macs_do_not_spend_the_parent_budget() {
    let limits = RateLimits {
        attest_per_session: 1,
        ..RateLimits::default()
    };
    let h = harness_with(TestSource::standard(), |b| b.rate_limits(limits)).await;
    let parent = exchange(&h).await;
    for _ in 0..3 {
        let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
        let forged = attest_req_with(&parent.id, &handoff.handoff_id, &[0u8; 32], PROCESS_ID);
        let (status, body) = post(&h.app, "/attest", &forged).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::HandoffInvalid)
        );
    }
    let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
    attest_ok(&h.app, &h.issuers, &parent.id, &handoff).await;
}

#[tokio::test]
async fn revocation_snapshots_still_reach_children() {
    let store = Arc::new(HookStore::default());
    let h = harness_with(TestSource::standard(), |b| {
        b.session_store(store.clone())
            .revocations(Arc::new(MemoryRevocations::new()))
    })
    .await;
    // Snapshots that list only roots stand in for a child attested after
    // the snapshot was taken.
    store
        .hide_children_from_snapshots
        .store(true, Ordering::SeqCst);
    for revoke_by_key in [false, true] {
        let parent = exchange(&h).await;
        let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
        let (child, _) = attest_ok(&h.app, &h.issuers, &parent.id, &handoff).await;
        let killed = if revoke_by_key {
            h.state.revoke_key_id(9).await.unwrap()
        } else {
            h.state.revoke_account(ACCOUNT).await.unwrap()
        };
        assert_eq!(killed, 2);
        let (status, body) = heartbeat(&h, &child).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
        );
    }
}

#[tokio::test]
async fn revoking_a_session_revokes_its_descendants() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let bystander = exchange(&h).await;
    let (child, _) = attest_ok(
        &h.app,
        &h.issuers,
        &parent.id,
        &handoff_ok(&h.app, &h.issuers, &parent).await,
    )
    .await;
    let (grandchild, _) = attest_ok(
        &h.app,
        &h.issuers,
        &child.id,
        &handoff_ok(&h.app, &h.issuers, &child).await,
    )
    .await;
    assert_eq!(h.state.revoke_session(parent.id).await.unwrap(), 3);
    for session in [&parent, &child, &grandchild] {
        let (status, body) = heartbeat(&h, session).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
        );
    }
    heartbeat_ok(&h, &bystander).await;
}

#[tokio::test]
async fn revoking_a_child_spares_the_parent() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let handoff = handoff_ok(&h.app, &h.issuers, &parent).await;
    let (child, _) = attest_ok(&h.app, &h.issuers, &parent.id, &handoff).await;
    assert_eq!(h.state.revoke_session(child.id).await.unwrap(), 1);
    heartbeat_ok(&h, &parent).await;
}

#[tokio::test]
async fn account_and_key_revocation_kill_every_session() {
    let h = harness_with(TestSource::standard(), |b| {
        b.revocations(Arc::new(MemoryRevocations::new()))
    })
    .await;
    let parent = exchange(&h).await;
    let (child, _) = attest_ok(
        &h.app,
        &h.issuers,
        &parent.id,
        &handoff_ok(&h.app, &h.issuers, &parent).await,
    )
    .await;
    assert_eq!(h.state.revoke_account(ACCOUNT).await.unwrap(), 2);
    for session in [&parent, &child] {
        let (status, body) = heartbeat(&h, session).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
        );
    }

    let parent = exchange(&h).await;
    let (child, _) = attest_ok(
        &h.app,
        &h.issuers,
        &parent.id,
        &handoff_ok(&h.app, &h.issuers, &parent).await,
    )
    .await;
    assert_eq!(h.state.revoke_key_id(9).await.unwrap(), 2);
    for session in [&parent, &child] {
        let (status, body) = heartbeat(&h, session).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
        );
    }
}

#[tokio::test]
async fn dead_parent_can_neither_mint_nor_redeem() {
    let h = harness().await;
    let parent = exchange(&h).await;
    let pending = handoff_ok(&h.app, &h.issuers, &parent).await;
    h.state.revoke_session(parent.id).await.unwrap();

    let (status, body) = post(
        &h.app,
        "/handoff",
        &handoff_req(&parent, PROCESS_ID, 60_000),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
    );
    let (status, body) = post(
        &h.app,
        "/attest",
        &attest_req(&parent.id, &pending, PROCESS_ID),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::UNPROCESSABLE_ENTITY, ErrorCode::HandoffInvalid)
    );
}
