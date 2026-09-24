//! Rate limiting: which requests are charged, to which bucket, and that map
//! pressure never locks out a key that is already tracked.

mod common;

use std::time::Duration as StdDuration;

use axum::Router;
use axum::http::StatusCode;
use chrono::Utc;
use common::*;
use keystone_core::wire::ErrorCode;
use keystone_server::{MemoryLimiter, RateLimiter, RateLimits, public_router};

fn limits(configure: impl FnOnce(&mut RateLimits)) -> RateLimits {
    let mut limits = RateLimits::default();
    configure(&mut limits);
    limits
}

fn from(h: &Harness, addr: &str) -> Router {
    with_peer(public_router(h.state.clone()), addr)
}

#[tokio::test]
async fn unknown_sessions_never_charge_session_buckets() {
    let h = harness_with(TestSource::standard(), |b| {
        b.rate_limits(limits(|l| l.heartbeat_per_session = 1))
    })
    .await;
    let stranger = Session {
        id: uuid::Uuid::new_v4(),
        key: [1u8; 32],
    };
    for _ in 0..5 {
        let (status, body) = heartbeat(&h, &stranger).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(code(&body), ErrorCode::UnknownSession);
    }
    let session = exchange(&h).await;
    heartbeat_ok(&h, &session).await;
    let (status, body) = heartbeat(&h, &session).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(code(&body), ErrorCode::RateLimited);
}

#[tokio::test]
async fn bad_macs_do_not_spend_the_session_budget() {
    let h = harness_with(TestSource::standard(), |b| {
        b.rate_limits(limits(|l| {
            l.heartbeat_per_session = 2;
            l.handoff_per_session = 2;
        }))
    })
    .await;
    let session = exchange(&h).await;
    let forged = Session {
        id: session.id,
        key: [0u8; 32],
    };
    for _ in 0..5 {
        let (status, body) = heartbeat(&h, &forged).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::UNAUTHORIZED, ErrorCode::InvalidMac)
        );
        let (status, body) = post(
            &h.app,
            "/handoff",
            &handoff_req(&forged, PROCESS_ID, 60_000),
        )
        .await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::UNAUTHORIZED, ErrorCode::InvalidMac)
        );
    }
    heartbeat_ok(&h, &session).await;
    handoff_ok(&h.app, &h.issuers, &session).await;
}

#[tokio::test]
async fn session_routes_share_a_per_ip_limit() {
    let h = harness_with(TestSource::standard(), |b| {
        b.rate_limits(limits(|l| l.session_per_ip = 2))
    })
    .await;
    let a = exchange(&h).await;
    let b = exchange(&h).await;
    let app = from(&h, "198.51.100.7:5000");
    for session in [&a, &b] {
        let (status, _) = post(
            &app,
            "/heartbeat",
            &heartbeat_req(session, nonce(), now_ms()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, body) = post(&app, "/handoff", &handoff_req(&a, PROCESS_ID, 60_000)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
    );

    let other = from(&h, "198.51.100.8:5000");
    let (status, _) = post(&other, "/handoff", &handoff_req(&a, PROCESS_ID, 60_000)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn ipv6_clients_are_bucketed_per_64() {
    let h = harness_with(TestSource::standard(), |b| {
        b.rate_limits(limits(|l| l.session_per_ip = 1))
    })
    .await;
    let session = exchange(&h).await;
    let first = from(&h, "[2001:db8:1:2::1]:4000");
    let same_prefix = from(&h, "[2001:db8:1:2:ffff::9]:4000");
    let other_prefix = from(&h, "[2001:db8:1:3::1]:4000");

    let (status, _) = post(
        &first,
        "/heartbeat",
        &heartbeat_req(&session, nonce(), now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = post(
        &same_prefix,
        "/heartbeat",
        &heartbeat_req(&session, nonce(), now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(code(&body), ErrorCode::RateLimited);
    let (status, _) = post(
        &other_prefix,
        "/heartbeat",
        &heartbeat_req(&session, nonce(), now_ms()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn successful_logins_do_not_charge_the_account() {
    let h = harness_with(TestSource::standard(), |b| {
        b.rate_limits(limits(|l| {
            l.exchange_failures_per_account = 2;
            l.exchange_failures_per_account_total = 2;
        }))
    })
    .await;
    for _ in 0..5 {
        exchange(&h).await;
    }
}

async fn wrong_secret(app: &Router, account: &str) -> (StatusCode, ErrorCode) {
    let (status, body) = post(app, "/exchange", &exchange_req(account, "nope", PRODUCT)).await;
    (status, code(&body))
}

#[tokio::test]
async fn failed_logins_lock_the_account_only_from_that_address() {
    let source = TestSource::standard();
    source.add(
        "other",
        "otherpass",
        vec![grant(PRODUCT, Utc::now() + chrono::Duration::days(1), &[])],
    );
    let h = harness_with(source, |b| {
        b.rate_limits(limits(|l| l.exchange_failures_per_account = 2))
    })
    .await;
    let attacker = from(&h, "203.0.113.5:1000");
    for _ in 0..2 {
        assert_eq!(
            wrong_secret(&attacker, ACCOUNT).await,
            (StatusCode::UNAUTHORIZED, ErrorCode::InvalidCredentials)
        );
    }
    let (status, body) = post(
        &attacker,
        "/exchange",
        &exchange_req(ACCOUNT, SECRET, PRODUCT),
    )
    .await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
    );

    let (status, _) = post(
        &attacker,
        "/exchange",
        &exchange_req("other", "otherpass", PRODUCT),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a second account is unaffected");
    let victim = from(&h, "198.51.100.20:1000");
    let (status, _) = post(
        &victim,
        "/exchange",
        &exchange_req(ACCOUNT, SECRET, PRODUCT),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owner still logs in from elsewhere"
    );
}

#[tokio::test]
async fn account_wide_ceiling_caps_failures_across_addresses() {
    let h = harness_with(TestSource::standard(), |b| {
        b.rate_limits(limits(|l| {
            l.exchange_failures_per_account = 5;
            l.exchange_failures_per_account_total = 3;
        }))
    })
    .await;
    for i in 0..3 {
        let app = from(&h, &format!("203.0.113.{i}:1000"));
        assert_eq!(
            wrong_secret(&app, ACCOUNT).await,
            (StatusCode::UNAUTHORIZED, ErrorCode::InvalidCredentials)
        );
    }
    let fresh = from(&h, "203.0.113.200:1000");
    assert_eq!(
        wrong_secret(&fresh, ACCOUNT).await,
        (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_wrong_secrets_are_bounded_by_the_failure_limit() {
    const LIMIT: u32 = 3;
    let h = harness_with(TestSource::standard(), |b| {
        b.rate_limits(limits(|l| {
            l.exchange_per_ip = 100;
            l.exchange_failures_per_account = LIMIT;
        }))
    })
    .await;
    let attempts: Vec<_> = (0..12)
        .map(|_| {
            let app = h.app.clone();
            tokio::spawn(async move { wrong_secret(&app, ACCOUNT).await })
        })
        .collect();
    let mut limited = 0;
    for attempt in attempts {
        let (status, code) = attempt.await.unwrap();
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(code, ErrorCode::RateLimited);
            limited += 1;
        }
    }
    assert!(h.source.authentications() <= LIMIT as usize);
    assert_eq!(limited, 12 - h.source.authentications());
}

#[tokio::test]
async fn full_limiter_never_denies_a_tracked_key() {
    let limiter = MemoryLimiter::with_capacity(4);
    let window = StdDuration::from_secs(60);
    assert!(limiter.check("steady", 1000, window).await);
    for i in 0..64 {
        assert!(limiter.check(&format!("flood-{i}"), 3, window).await);
        assert!(limiter.check("steady", 1000, window).await);
    }
}

#[tokio::test]
async fn peek_does_not_charge_and_refund_returns_a_hit() {
    let limiter = MemoryLimiter::new();
    let window = StdDuration::from_secs(60);
    for _ in 0..10 {
        assert!(limiter.peek("k", 1, window).await);
    }
    assert!(limiter.check("k", 1, window).await);
    assert!(!limiter.peek("k", 1, window).await);
    assert!(!limiter.check("k", 1, window).await);
    limiter.refund("k").await;
    assert!(limiter.check("k", 1, window).await);
}
