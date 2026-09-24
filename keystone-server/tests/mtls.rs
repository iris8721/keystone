//! The real `serve` over mTLS: certificate identity at exchange and attest,
//! certificate continuity for every session request, the admin listener,
//! and graceful shutdown.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use common::*;
use keystone_core::wire::{
    ADMIN_TOKEN_HEADER, AUDIENCE_APP, AUDIENCE_CLIENT, AttestBody, BUILD_ID_HEADER, ErrorCode,
    HandoffBody, OP_ATTEST, OP_EXCHANGE, OP_HANDOFF, RevokeBody, RevokeRequest, RevokeTarget,
    paths,
};
use keystone_core::{handoff_wrap_key, unwrap_secret};
use keystone_server::{AdminToken, PayloadConfig, RateLimits};
use zeroize::Zeroizing;

/// A state that, like production mTLS, requires client certificates.
async fn mtls_harness() -> Harness {
    harness_with(TestSource::standard(), |b| {
        b.require_client_certificates(true)
    })
    .await
}

async fn tls_exchange(
    h: &Harness,
    client: &reqwest::Client,
    server: &TlsServer,
) -> Result<Session, (u16, ErrorCode)> {
    let req = exchange_req(ACCOUNT, SECRET, PRODUCT);
    let (status, value) = https_post(client, server.public, "/exchange", &req).await;
    if status != 200 {
        return Err((status, code(&value)));
    }
    let (_, body): (_, keystone_core::wire::ExchangeBody) = open(
        &h.issuers,
        &value,
        req.challenge,
        None,
        AUDIENCE_CLIENT,
        OP_EXCHANGE,
    );
    Ok(Session {
        id: body.session_id,
        key: *body.session_key,
    })
}

async fn tls_heartbeat(
    client: &reqwest::Client,
    server: &TlsServer,
    session: &Session,
) -> (u16, Option<ErrorCode>) {
    let (status, value) = https_post(
        client,
        server.public,
        "/heartbeat",
        &heartbeat_req(session, nonce(), now_ms()),
    )
    .await;
    (status, (status != 200).then(|| code(&value)))
}

#[tokio::test]
async fn client_without_certificate_is_refused_at_handshake() {
    let h = mtls_harness().await;
    let ca = make_ca();
    let server = spawn_mtls(h.state.clone(), &ca, false);
    let result = https_client(&ca, None)
        .post(format!("https://{}/exchange", server.public))
        .header("keystone-protocol", "2")
        .json(&exchange_req(ACCOUNT, SECRET, PRODUCT))
        .send()
        .await;
    assert!(result.is_err(), "handshake without a client cert succeeded");
}

#[tokio::test]
async fn exchange_requires_the_certificate_to_name_the_account() {
    let h = mtls_harness().await;
    let ca = make_ca();
    let server = spawn_mtls(h.state.clone(), &ca, false);
    let mallory = https_client(&ca, Some(&client_cert(&ca, "mallory")));
    assert_eq!(
        tls_exchange(&h, &mallory, &server).await.err(),
        Some((401, ErrorCode::InvalidCredentials))
    );
    let dev = https_client(&ca, Some(&client_cert(&ca, ACCOUNT)));
    assert!(tls_exchange(&h, &dev, &server).await.is_ok());
}

#[tokio::test]
async fn every_session_is_bound_to_its_exchange_certificate() {
    let h = mtls_harness().await;
    let ca = make_ca();
    let server = spawn_mtls(h.state.clone(), &ca, false);
    let first = https_client(&ca, Some(&client_cert(&ca, ACCOUNT)));
    let second = https_client(&ca, Some(&client_cert(&ca, ACCOUNT)));
    let session = tls_exchange(&h, &first, &server).await.unwrap();

    assert_eq!(
        tls_heartbeat(&second, &server, &session).await,
        (401, Some(ErrorCode::InvalidMac))
    );
    assert_eq!(tls_heartbeat(&first, &server, &session).await, (200, None));
}

#[tokio::test]
async fn pinned_account_accepts_only_the_pinned_certificate() {
    let h = mtls_harness().await;
    let ca = make_ca();
    let pinned = client_cert(&ca, ACCOUNT);
    h.source.pin(ACCOUNT, pinned.sha256);
    let server = spawn_mtls(h.state.clone(), &ca, false);
    let impostor = https_client(&ca, Some(&client_cert(&ca, ACCOUNT)));
    assert_eq!(
        tls_exchange(&h, &impostor, &server).await.err(),
        Some((401, ErrorCode::InvalidCredentials))
    );
    let owner = https_client(&ca, Some(&pinned));
    let session = tls_exchange(&h, &owner, &server).await.unwrap();
    assert_eq!(tls_heartbeat(&owner, &server, &session).await, (200, None));
}

#[tokio::test]
async fn child_sessions_bind_to_the_attesting_certificate() {
    let h = mtls_harness().await;
    let ca = make_ca();
    let server = spawn_mtls(h.state.clone(), &ca, false);
    let loader = https_client(&ca, Some(&client_cert(&ca, ACCOUNT)));
    let app = https_client(&ca, Some(&client_cert(&ca, ACCOUNT)));
    let parent = tls_exchange(&h, &loader, &server).await.unwrap();

    let mint = |client: reqwest::Client| {
        let parent = parent.clone();
        let issuers = h.issuers.clone();
        let addr = server.public;
        async move {
            let req = handoff_req(&parent, PROCESS_ID, 60_000);
            let (status, value) = https_post(&client, addr, "/handoff", &req).await;
            assert_eq!(status, 200, "{value}");
            open::<HandoffBody>(
                &issuers,
                &value,
                req.nonce,
                Some(parent.id),
                AUDIENCE_CLIENT,
                OP_HANDOFF,
            )
            .1
        }
    };
    let (status, _) = https_post(
        &app,
        server.public,
        "/handoff",
        &handoff_req(&parent, PROCESS_ID, 60_000),
    )
    .await;
    assert_eq!(
        status, 401,
        "a different certificate cannot act for the loader session"
    );

    let handoff = mint(loader.clone()).await;
    let mallory = https_client(&ca, Some(&client_cert(&ca, "mallory")));
    let (status, value) = https_post(
        &mallory,
        server.public,
        "/attest",
        &attest_req(&parent.id, &handoff, PROCESS_ID),
    )
    .await;
    assert_eq!((status, code(&value)), (401, ErrorCode::InvalidCredentials));

    let handoff = mint(loader.clone()).await;
    let req = attest_req(&parent.id, &handoff, PROCESS_ID);
    let (status, value) = https_post(&app, server.public, "/attest", &req).await;
    assert_eq!(status, 200, "{value}");
    let (_, body): (_, AttestBody) = open(
        &h.issuers,
        &value,
        req.challenge,
        None,
        AUDIENCE_APP,
        OP_ATTEST,
    );
    let key = unwrap_secret(
        &handoff_wrap_key(&handoff.handoff_secret, &req.challenge),
        &body.session_key_wrap,
    )
    .unwrap();
    let child = Session {
        id: body.session_id,
        key: *key,
    };
    assert_eq!(
        tls_heartbeat(&loader, &server, &child).await,
        (401, Some(ErrorCode::InvalidMac))
    );
    assert_eq!(tls_heartbeat(&app, &server, &child).await, (200, None));
}

/// An mTLS state with the admin listener allowing only `operator`.
async fn admin_harness(operator: &ClientCert, limits: RateLimits) -> Harness {
    let allowed = BTreeSet::from([operator.sha256]);
    harness_with(TestSource::standard(), move |b| {
        b.require_client_certificates(true)
            .admin_token(AdminToken::new(ADMIN_TOKEN).unwrap())
            .admin_certificates(allowed)
            .rate_limits(limits)
            .payloads(PayloadConfig::new(temp_dir("mtls-publish"), [9u8; 32], 0))
    })
    .await
}

#[tokio::test]
async fn revoke_is_served_only_on_the_admin_listener() {
    let ca = make_ca();
    let operator_cert = client_cert(&ca, "operator");
    let h = admin_harness(&operator_cert, RateLimits::default()).await;
    let server = spawn_mtls(h.state.clone(), &ca, true);
    let client = https_client(&ca, Some(&client_cert(&ca, ACCOUNT)));
    let session = tls_exchange(&h, &client, &server).await.unwrap();
    let revoke = RevokeRequest {
        admin_token: Zeroizing::new(ADMIN_TOKEN.to_string()),
        target: RevokeTarget::Session(session.id),
    };

    let (status, value) = https_post(&client, server.public, "/revoke", &revoke).await;
    assert_eq!((status, code(&value)), (404, ErrorCode::BadRequest));
    assert_eq!(tls_heartbeat(&client, &server, &session).await, (200, None));

    let operator = https_client(&ca, Some(&operator_cert));
    let admin = server.admin.unwrap();
    let (status, value) = https_post(&operator, admin, "/revoke", &revoke).await;
    assert_eq!(status, 200, "{value}");
    assert_eq!(
        serde_json::from_value::<RevokeBody>(value).unwrap().revoked,
        1
    );
    assert_eq!(
        tls_heartbeat(&client, &server, &session).await,
        (403, Some(ErrorCode::SessionRevoked))
    );

    let anonymous = https_client(&ca, None)
        .post(format!("https://{admin}/revoke"))
        .header("keystone-protocol", "2")
        .json(&revoke)
        .send()
        .await;
    assert!(
        anonymous.is_err(),
        "admin listener accepted a client without a certificate"
    );
}

#[tokio::test]
async fn customer_certificates_are_refused_on_the_admin_listener_without_charge() {
    let ca = make_ca();
    let operator_cert = client_cert(&ca, "operator");
    let limits = RateLimits {
        admin_failures_per_ip: 1,
        ..RateLimits::default()
    };
    let h = admin_harness(&operator_cert, limits).await;
    let server = spawn_mtls(h.state.clone(), &ca, true);
    let admin = server.admin.unwrap();
    let customer = https_client(&ca, Some(&client_cert(&ca, ACCOUNT)));
    let revoke = RevokeRequest {
        admin_token: Zeroizing::new(ADMIN_TOKEN.to_string()),
        target: RevokeTarget::Account("nobody".into()),
    };
    for _ in 0..3 {
        let (status, value) = https_post(&customer, admin, "/revoke", &revoke).await;
        assert_eq!((status, code(&value)), (403, ErrorCode::Forbidden));
    }
    let publish = customer
        .put(format!(
            "https://{admin}{}",
            paths::artifact(PRODUCT, "1.0.0")
        ))
        .header("keystone-protocol", "2")
        .header(ADMIN_TOKEN_HEADER, ADMIN_TOKEN)
        .header(BUILD_ID_HEADER, "b1")
        .body("bytes")
        .send()
        .await
        .unwrap();
    assert_eq!(publish.status().as_u16(), 403);

    let operator = https_client(&ca, Some(&operator_cert));
    let (status, value) = https_post(&operator, admin, "/revoke", &revoke).await;
    assert_eq!(
        status, 200,
        "customer attempts spent the operator's budget: {value}"
    );
}

#[tokio::test]
async fn another_customers_certificate_cannot_lock_out_an_account() {
    let limits = RateLimits {
        exchange_failures_per_account: 2,
        ..RateLimits::default()
    };
    let h = harness_with(TestSource::standard(), |b| {
        b.require_client_certificates(true).rate_limits(limits)
    })
    .await;
    let ca = make_ca();
    let server = spawn_mtls(h.state.clone(), &ca, false);
    let mallory = https_client(&ca, Some(&client_cert(&ca, "mallory")));
    let mut outcomes = Vec::new();
    for _ in 0..4 {
        outcomes.push(tls_exchange(&h, &mallory, &server).await.err());
    }
    assert_eq!(
        outcomes,
        [
            Some((401, ErrorCode::InvalidCredentials)),
            Some((401, ErrorCode::InvalidCredentials)),
            Some((429, ErrorCode::RateLimited)),
            Some((429, ErrorCode::RateLimited)),
        ]
    );
    let owner = https_client(&ca, Some(&client_cert(&ca, ACCOUNT)));
    assert!(tls_exchange(&h, &owner, &server).await.is_ok());
}

#[tokio::test]
async fn shutdown_stops_both_listeners() {
    let ca = make_ca();
    let operator_cert = client_cert(&ca, "operator");
    let h = admin_harness(&operator_cert, RateLimits::default()).await;
    let mut server = spawn_mtls(h.state.clone(), &ca, true);
    let client = https_client(&ca, Some(&client_cert(&ca, ACCOUNT)));
    tls_exchange(&h, &client, &server).await.unwrap();

    server.shutdown.take().unwrap().send(()).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(15), &mut server.task)
        .await
        .expect("serve returns after shutdown")
        .unwrap();
    assert!(outcome.is_ok());
    for addr in [server.public, server.admin.unwrap()] {
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "{addr} still accepts connections"
        );
    }
}
