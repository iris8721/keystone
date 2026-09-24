//! Server authentication: SPKI pins (rotation sets, rejection before any
//! request, hostname bypass) and the unpinned WebPKI hostname check.

use crate::common::*;
use keystone_client::{ClientError, KeystoneClient};

async fn exchange_with(client: &KeystoneClient) -> Result<(), ClientError> {
    client
        .exchange(ACCOUNT, SECRET, PRODUCT, HWID)
        .await
        .map(drop)
}

fn assert_transport(result: Result<(), ClientError>) {
    match result {
        Err(ClientError::Transport(_)) => {}
        other => panic!("expected a TLS failure, got {other:?}"),
    }
}

#[tokio::test]
async fn pin_set_accepts_the_current_or_the_next_key() {
    let current = rig().await;
    let next = rig().await;
    let pins = [current.server_spki, next.server_spki];
    for rig in [&current, &next] {
        let client = pins
            .iter()
            .fold(rig.bare_builder(rig.server.public), |b, pin| {
                b.pin_spki(*pin)
            })
            .server_ca_pem(rig.ca.pem())
            .build()
            .unwrap();
        exchange_with(&client).await.expect("pinned key accepted");
    }
}

#[tokio::test]
async fn wrong_pin_fails_before_any_request_is_sent() {
    let rig = rig().await;
    let wrong = rig
        .bare_builder(rig.server.public)
        .server_ca_pem(rig.ca.pem())
        .pin_spki([0xAB; 32])
        .build()
        .unwrap();
    assert_transport(exchange_with(&wrong).await);
    assert_eq!(rig.source.logins(), 0, "no request reached the server");

    let right = rig
        .bare_builder(rig.server.public)
        .server_ca_pem(rig.ca.pem())
        .pin_spki(rig.server_spki)
        .build()
        .unwrap();
    exchange_with(&right).await.unwrap();
    assert_eq!(rig.source.logins(), 1);
}

#[tokio::test]
async fn pin_replaces_the_hostname_check() {
    let rig = Rig::start(TestSource::standard(), &["elsewhere.example"], |b| b).await;
    let with_ca = rig
        .bare_builder(rig.server.public)
        .server_ca_pem(rig.ca.pem())
        .pin_spki(rig.server_spki)
        .build()
        .unwrap();
    exchange_with(&with_ca)
        .await
        .expect("pin + CA ignores the SAN");
    let pin_only = rig
        .bare_builder(rig.server.public)
        .pin_spki(rig.server_spki)
        .build()
        .unwrap();
    exchange_with(&pin_only)
        .await
        .expect("pin alone ignores the SAN");
}

#[tokio::test]
async fn unpinned_client_rejects_a_wrong_hostname() {
    let rig = Rig::start(TestSource::standard(), &["elsewhere.example"], |b| b).await;
    assert_transport(exchange_with(&rig.client()).await);
    assert_eq!(rig.source.logins(), 0);
}
