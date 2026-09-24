//! Handoff v2 in-process: token transport, single-use attestation, and a
//! child session that stands on its own.

use std::time::{Duration as StdDuration, Instant};

use chrono::Duration;
use keystone_client::{
    ClientError, DEFAULT_HANDOFF_TTL, DeadReason, ErrorCode, HandoffToken, PendingSession,
};

use crate::common::*;

#[tokio::test]
async fn child_attests_and_outlives_the_loader_lease() {
    let rig = rig_with(|b| b.lease_ttl(Duration::seconds(4))).await;
    let client = rig.client();
    let loader = rig.exchange(&client).await;
    let loader_id = loader.session_id();
    let token = client
        .create_handoff(&loader, PROCESS_ID, DEFAULT_HANDOFF_TTL)
        .await
        .expect("handoff");

    let mut pipe = Vec::new();
    HandoffToken::decode(&token.encode())
        .unwrap()
        .write_to(&mut pipe)
        .unwrap();
    let received = HandoffToken::read_from(&pipe[..]).unwrap();
    let pending = PendingSession::from_handoff(received, PROCESS_ID).unwrap();
    assert_eq!(pending.parent_session_id(), loader_id);
    assert_eq!(pending.product(), PRODUCT);

    let child = client.attest(pending).await.expect("attest");
    assert_ne!(child.session_id(), loader_id);
    assert_eq!(child.product(), PRODUCT);
    assert!(child.gate().has_feature("all"));

    // The loader never renews; the child renews until the loader has lapsed.
    let deadline = Instant::now() + StdDuration::from_secs(20);
    while loader.is_alive() {
        assert!(Instant::now() < deadline, "loader lease never lapsed");
        client
            .heartbeat(&child)
            .await
            .expect("child renews independently");
        tokio::time::sleep(StdDuration::from_millis(500)).await;
    }
    assert_eq!(loader.dead_reason(), Some(DeadReason::Expired));
    client
        .heartbeat(&child)
        .await
        .expect("child renews after the loader lease lapsed");
    assert!(child.is_alive());
}

#[tokio::test]
async fn second_attest_with_the_same_token_is_handoff_invalid() {
    let rig = rig().await;
    let client = rig.client();
    let loader = rig.exchange(&client).await;
    let encoded = client
        .create_handoff(&loader, PROCESS_ID, DEFAULT_HANDOFF_TTL)
        .await
        .unwrap()
        .encode();
    let open = || {
        PendingSession::from_handoff(HandoffToken::decode(&encoded).unwrap(), PROCESS_ID).unwrap()
    };

    let child = client.attest(open()).await.expect("first attest");
    let err = client.attest(open()).await.unwrap_err();
    match err {
        ClientError::ServerRejected { code, .. } => {
            assert_eq!(code, Some(ErrorCode::HandoffInvalid))
        }
        other => panic!("expected handoff_invalid, got {other:?}"),
    }

    // The refused replay leaves both sessions intact.
    client.heartbeat(&child).await.unwrap();
    client.heartbeat(&loader).await.unwrap();
}
