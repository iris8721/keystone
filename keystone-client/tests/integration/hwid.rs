//! `AdminClient` against the machine-binding admin routes over mTLS.

use keystone_client::{AdminClient, ClientError, ErrorCode};
use sha2::{Digest, Sha256};

use crate::common::*;

const OTHER_HWID: [u8; 32] = [0x5e; 32];

fn rejection(err: &ClientError) -> (u16, Option<ErrorCode>) {
    match err {
        ClientError::ServerRejected { status, code, .. } => (*status, *code),
        other => panic!("expected a server rejection, got {other:?}"),
    }
}

/// An operator client that presents the wrong admin token.
fn admin_with_wrong_token(rig: &Rig) -> AdminClient {
    AdminClient::builder(https_url(rig.server.admin))
        .server_ca_pem(rig.ca.pem())
        .identity(rig.identity.clone())
        .admin_token(format!("{ADMIN_TOKEN}x"))
        .build()
        .unwrap()
}

#[tokio::test]
async fn account_info_reports_the_lock_and_the_grants() {
    let rig = rig().await;
    let admin = rig.admin();

    let info = admin.account_info(ACCOUNT).await.expect("account info");
    assert_eq!(info.name, ACCOUNT);
    assert!(!info.hwid_locked);
    assert_eq!(
        info.entitlements
            .iter()
            .map(|g| g.product.as_str())
            .collect::<Vec<_>>(),
        [PRODUCT]
    );

    rig.exchange(&rig.client()).await;
    assert_eq!(rig.source.hwid_lock(), Some(Sha256::digest(HWID).into()));
    assert!(
        admin
            .account_info(ACCOUNT)
            .await
            .expect("account info")
            .hwid_locked
    );
}

#[tokio::test]
async fn a_reset_lets_another_machine_in() {
    let rig = rig().await;
    let client = rig.client();
    rig.exchange(&client).await;

    // The bound machine is the only one that may log in.
    let err = client
        .exchange(ACCOUNT, SECRET, PRODUCT, OTHER_HWID)
        .await
        .unwrap_err();
    assert_eq!(
        rejection(&err),
        (403, Some(ErrorCode::HwidMismatch)),
        "a stranger machine must be refused"
    );

    let body = rig.admin().hwid_reset(ACCOUNT).await.expect("reset");
    assert_eq!(body.account, ACCOUNT);
    assert!(body.was_locked);
    // Nothing is left to clear until another machine binds.
    assert!(
        !rig.admin()
            .hwid_reset(ACCOUNT)
            .await
            .expect("reset")
            .was_locked
    );

    client
        .exchange(ACCOUNT, SECRET, PRODUCT, OTHER_HWID)
        .await
        .expect("the reset machine binds anew");
    assert_eq!(
        rig.source.hwid_lock(),
        Some(Sha256::digest(OTHER_HWID).into())
    );
}

#[tokio::test]
async fn unknown_accounts_are_not_found() {
    let rig = rig().await;
    let admin = rig.admin();
    let err = admin.hwid_reset("nobody").await.unwrap_err();
    assert_eq!(rejection(&err), (404, Some(ErrorCode::BadRequest)));
    let err = admin.account_info("nobody").await.unwrap_err();
    assert_eq!(rejection(&err), (404, Some(ErrorCode::BadRequest)));
}

#[tokio::test]
async fn the_admin_routes_refuse_a_wrong_token() {
    let rig = rig().await;
    let admin = admin_with_wrong_token(&rig);
    let err = admin.hwid_reset(ACCOUNT).await.unwrap_err();
    assert_eq!(rejection(&err), (403, Some(ErrorCode::Forbidden)));
    let err = admin.account_info(ACCOUNT).await.unwrap_err();
    assert_eq!(rejection(&err), (403, Some(ErrorCode::Forbidden)));
}
