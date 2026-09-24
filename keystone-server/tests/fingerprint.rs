//! HWID fingerprints are an anomaly signal: a changed fingerprint inside
//! the window is audited, never denied.

mod common;

use common::*;
use keystone_server::AuditEvent;

fn anomalies(h: &Harness) -> usize {
    h.audit
        .events()
        .iter()
        .filter(|e| matches!(e, AuditEvent::HwidAnomaly { .. }))
        .count()
}

#[tokio::test]
async fn same_fingerprint_is_not_anomalous() {
    let h = harness().await;
    exchange(&h).await;
    exchange(&h).await;
    assert_eq!(anomalies(&h), 0);
}

#[tokio::test]
async fn changed_fingerprint_is_audited_but_allowed() {
    let h = harness().await;
    exchange(&h).await;
    let mut req = exchange_req(ACCOUNT, SECRET, PRODUCT);
    req.hwid = [9u8; 32];
    exchange_with(&h, req).await;
    assert_eq!(anomalies(&h), 1);
    assert!(h.audit.events().contains(&AuditEvent::HwidAnomaly {
        account: ACCOUNT.to_string()
    }));
}

#[tokio::test]
async fn fingerprints_are_per_account() {
    let h = harness().await;
    h.source.add(
        "alice",
        "alicepass",
        vec![grant(
            PRODUCT,
            chrono::Utc::now() + chrono::Duration::days(1),
            &[],
        )],
    );
    exchange(&h).await;
    let mut req = exchange_req("alice", "alicepass", PRODUCT);
    req.hwid = [9u8; 32];
    exchange_with(&h, req).await;
    assert_eq!(anomalies(&h), 0);
}

#[tokio::test]
async fn exchanges_are_audited() {
    let h = harness().await;
    let session = exchange(&h).await;
    post(
        &h.app,
        "/exchange",
        &exchange_req(ACCOUNT, "wrong", PRODUCT),
    )
    .await;
    let events = h.audit.events();
    assert!(events.contains(&AuditEvent::ExchangeSucceeded {
        account: ACCOUNT.to_string(),
        product: PRODUCT.to_string(),
        session_id: session.id,
    }));
    assert!(events.iter().any(|e| matches!(
        e,
        AuditEvent::ExchangeDenied {
            reason: keystone_core::wire::ErrorCode::InvalidCredentials,
            ..
        }
    )));
}
