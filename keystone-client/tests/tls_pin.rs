//! SPKI pinning + client-cert tests: a live TLS handshake against a
//! real rustls server, exercising `KeystoneClient::new` end to
//! end — CA-only trust roots, the leaf SPKI pin, and mTLS identity.

use std::net::SocketAddr;

use axum::{Json, Router, routing::post};
use keystone_client::{ClientIdentity, KeystoneClient};
use keystone_core::{Issuer, TrustedIssuers};
use keystone_server::tls::{PeerCertAcceptor, load_rustls_config};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const ISSUER_SEED: [u8; 32] = [7u8; 32];

struct TestCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

fn make_ca() -> TestCa {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test-ca");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    TestCa { cert, key }
}

/// Server cert (CN=localhost, SANs localhost + 127.0.0.1) signed by
/// `ca`. Returns (cert PEM, key PEM, leaf SPKI sha256).
fn issue_server_cert(ca: &TestCa) -> (String, String, [u8; 32]) {
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    let ee = webpki::EndEntityCert::try_from(cert.der()).unwrap();
    let spki: [u8; 32] = Sha256::digest(ee.subject_public_key_info()).into();
    (cert.pem(), key.serialize_pem(), spki)
}

fn issue_client_cert(ca: &TestCa, cn: &str) -> (String, String) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn issuers() -> TrustedIssuers {
    TrustedIssuers::single(1, Issuer::from_seed(&ISSUER_SEED, 1).verifying_key())
}

/// A minimal stand-in for the keystone router: /revoke answers 200
/// with an empty object, which is all `KeystoneClient::revoke` needs.
/// The point of these tests is the TLS layer, not the endpoints.
fn stub_router() -> Router {
    async fn revoke() -> Json<Value> {
        Json(json!({}))
    }
    Router::new().route("/revoke", post(revoke))
}

/// Drive one request through the pinned client. Any route works — the
/// verdict under test is the handshake, not the endpoint.
async fn probe(client: &KeystoneClient) -> Result<(), keystone_client::ClientError> {
    client.revoke(Uuid::nil(), "stub").await
}

/// Serve `stub_router` over TLS. `require_client_cert` installs the CA
/// as a client-cert verifier (mTLS).
async fn spawn_tls_server(
    ca: &TestCa,
    server_pem: &str,
    server_key_pem: &str,
    require_client_cert: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let ca_pem = require_client_cert.then(|| ca.cert.pem());
    let config = load_rustls_config(
        server_pem.as_bytes(),
        server_key_pem.as_bytes(),
        ca_pem.as_deref().map(str::as_bytes),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum_server::Server::from_tcp(listener)
            .acceptor(PeerCertAcceptor::new(config))
            .serve(stub_router().into_make_service())
            .await
            .unwrap();
    });
    (addr, handle)
}

#[tokio::test]
async fn correct_spki_pin_connects() {
    let ca = make_ca();
    let (cert_pem, key_pem, spki) = issue_server_cert(&ca);
    let (addr, _server) = spawn_tls_server(&ca, &cert_pem, &key_pem, false).await;

    let client = KeystoneClient::new(
        format!("https://{addr}"),
        issuers(),
        ca.cert.pem(),
        spki,
        None,
    )
    .unwrap();
    probe(&client)
        .await
        .expect("correct SPKI pin must complete the handshake");
}

#[tokio::test]
async fn wrong_spki_pin_fails_handshake() {
    let ca = make_ca();
    let (cert_pem, key_pem, _spki) = issue_server_cert(&ca);
    let (addr, _server) = spawn_tls_server(&ca, &cert_pem, &key_pem, false).await;

    // A different key's SPKI: chain validation passes (same CA), the
    // pin must be what kills it.
    let wrong_pin = [0xabu8; 32];
    let client = KeystoneClient::new(
        format!("https://{addr}"),
        issuers(),
        ca.cert.pem(),
        wrong_pin,
        None,
    )
    .unwrap();
    let err = probe(&client)
        .await
        .expect_err("wrong SPKI pin must fail the handshake");
    assert!(
        matches!(err, keystone_client::ClientError::Transport(_)),
        "expected a transport error, got {err}"
    );
}

#[tokio::test]
async fn cert_from_untrusted_ca_fails() {
    let ca = make_ca();
    let rogue_ca = make_ca();
    // Server cert signed by a DIFFERENT CA — the pin matches nothing
    // here; chain validation against the keystone CA must reject it.
    let (cert_pem, key_pem, spki) = issue_server_cert(&rogue_ca);
    let (addr, _server) = spawn_tls_server(&rogue_ca, &cert_pem, &key_pem, false).await;

    let client = KeystoneClient::new(
        format!("https://{addr}"),
        issuers(),
        ca.cert.pem(),
        spki,
        None,
    )
    .unwrap();
    probe(&client)
        .await
        .expect_err("a cert outside the keystone CA must fail");
}

#[tokio::test]
async fn mtls_identity_completes_handshake() {
    let ca = make_ca();
    let (cert_pem, key_pem, spki) = issue_server_cert(&ca);
    let (addr, _server) = spawn_tls_server(&ca, &cert_pem, &key_pem, true).await;
    let (client_cert, client_key) = issue_client_cert(&ca, "dev");

    // Without a client cert the handshake dies at the TLS layer.
    let no_cert = KeystoneClient::new(
        format!("https://{addr}"),
        issuers(),
        ca.cert.pem(),
        spki,
        None,
    )
    .unwrap();
    probe(&no_cert)
        .await
        .expect_err("mTLS server must reject a client with no cert");

    // With the CA-issued identity it completes.
    let with_cert = KeystoneClient::new(
        format!("https://{addr}"),
        issuers(),
        ca.cert.pem(),
        spki,
        Some(ClientIdentity {
            cert_pem: client_cert.into_bytes(),
            key_pem: client_key.into_bytes(),
        }),
    )
    .unwrap();
    probe(&with_cert)
        .await
        .expect("client cert must complete the mTLS handshake");
}

/// The pin must never mask chain validation: a cert whose SPKI matches
/// the pin but whose SAN doesn't cover the host is still rejected —
/// the pin only ever ADDS a rejection, it can't substitute for WebPKI.
#[tokio::test]
async fn correct_spki_wrong_san_fails() {
    let ca = make_ca();
    // Server cert for a DIFFERENT name — valid chain, wrong SAN.
    let mut params =
        rcgen::CertificateParams::new(vec!["not-localhost.example".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "not-localhost.example");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    let ee = webpki::EndEntityCert::try_from(cert.der()).unwrap();
    let spki: [u8; 32] = Sha256::digest(ee.subject_public_key_info()).into();
    let (addr, _server) = spawn_tls_server(&ca, &cert.pem(), &key.serialize_pem(), false).await;

    let client = KeystoneClient::new(
        format!("https://{addr}"),
        issuers(),
        ca.cert.pem(),
        spki, // the pin MATCHES — only the SAN is wrong
        None,
    )
    .unwrap();
    let err = probe(&client)
        .await
        .expect_err("a pinned SPKI must not rescue a wrong-SAN cert");
    assert!(
        matches!(err, keystone_client::ClientError::Transport(_)),
        "expected a transport error, got {err}"
    );
}
