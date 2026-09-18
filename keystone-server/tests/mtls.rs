//! mTLS tests: a live rustls handshake against the real router.
//!
//! Covers the three guarantees the cert_sha256 account binding rests
//! on: the transport refuses clients without a CA-issued cert, the
//! exchange handler rejects a valid-but-wrong cert for a pinned
//! account, and the pinned cert itself passes.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use keystone_core::{
    AccountIdentity, Entitlement, EntitlementSource, Issuer, KeystoneError,
};
use keystone_server::state::{ArtifactHashes, ChallengeBook, RateLimiter, RateLimits};
use keystone_server::tls::{load_rustls_config, PeerCertAcceptor};
use keystone_server::{build_router, AppState, SessionStore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ACCOUNT: &str = "dev";
const SECRET: &str = "devpass";
const PRODUCT: &str = "dev-product";

/// A CA + the certs it has issued, all in memory.
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

/// Issue a client cert with CN = `cn` under `ca`. Returns
/// (cert PEM, key PEM, cert DER sha256).
fn issue_client_cert(ca: &TestCa, cn: &str) -> (String, String, [u8; 32]) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    let sha: [u8; 32] = Sha256::digest(cert.der().as_ref()).into();
    (cert.pem(), key.serialize_pem(), sha)
}

/// Issue a server cert (CN=localhost, SANs localhost + 127.0.0.1).
fn issue_server_cert(ca: &TestCa) -> (String, String) {
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (cert.pem(), key.serialize_pem())
}

/// Entitlement source with a cert_sha256 pin — the stub has no cert
/// binding, so this wraps it and answers cert_sha256 from a table.
struct PinnedSource {
    inner: keystone_server::entitlement::StubEntitlementSource,
    pins: std::collections::HashMap<String, [u8; 32]>,
}

#[async_trait]
impl EntitlementSource for PinnedSource {
    async fn authenticate(
        &self,
        account: &str,
        secret: &str,
    ) -> Result<Option<AccountIdentity>, KeystoneError> {
        self.inner.authenticate(account, secret).await
    }

    async fn entitlement(
        &self,
        account: &str,
        product: &str,
    ) -> Result<Option<Entitlement>, KeystoneError> {
        self.inner.entitlement(account, product).await
    }

    async fn cert_sha256(&self, account: &str) -> Result<Option<[u8; 32]>, KeystoneError> {
        Ok(self.pins.get(account).copied())
    }
}

fn test_state(pin: Option<(&str, [u8; 32])>) -> AppState {
    let stub = keystone_server::entitlement::StubEntitlementSource::new(vec![(
        ACCOUNT.to_string(),
        SECRET.to_string(),
        vec![Entitlement {
            account: ACCOUNT.to_string(),
            product: PRODUCT.to_string(),
            expires_at: Utc::now() + Duration::days(30),
            features: vec!["all".to_string()],
        }],
    )]);
    let mut pins = std::collections::HashMap::new();
    if let Some((account, hash)) = pin {
        pins.insert(account.to_string(), hash);
    }
    AppState {
        issuer: Arc::new(Issuer::from_bytes(&[7u8; 32])),
        store: SessionStore::new(),
        entitlements: Arc::new(PinnedSource { inner: stub, pins }),
        challenges: Arc::new(ChallengeBook::new()),
        admin_token_hash: None,
        challenge_ttl: Duration::seconds(60),
        lease_ttl: Duration::seconds(300),
        grace_period: Duration::seconds(60),
        payload_dir: None,
        payload_secret: None,
        downloads: None,
        watermark_secret: None,
        rate_limits: RateLimits::default(),
        rate_limiter: Arc::new(RateLimiter::new()),
        artifact_hashes: Arc::new(ArtifactHashes::new()),
    }
}

/// Serve the real router over mTLS on an ephemeral port.
async fn spawn_mtls_server(state: AppState, ca: &TestCa) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let (cert_pem, key_pem) = issue_server_cert(ca);
    let config = load_rustls_config(
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
        Some(ca.cert.pem().as_bytes()),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum_server::Server::from_tcp(listener)
            .acceptor(PeerCertAcceptor::new(config))
            .serve(build_router(state).into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    (addr, handle)
}

/// reqwest client trusting only the test CA, optionally with a client
/// identity (cert PEM + key PEM concatenated).
fn http_client(ca: &TestCa, identity: Option<(&str, &str)>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(ca.cert.pem().as_bytes()).unwrap());
    if let Some((cert_pem, key_pem)) = identity {
        let bundle = format!("{cert_pem}{key_pem}");
        builder = builder.identity(reqwest::Identity::from_pem(bundle.as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

/// POST /challenge then /exchange; returns the exchange status + body.
async fn exchange(client: &reqwest::Client, addr: SocketAddr) -> (u16, Value) {
    let base = format!("https://{addr}");
    let challenge: Value = client
        .post(format!("{base}/challenge"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nonce: Vec<u8> = challenge["nonce"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect();
    let resp = client
        .post(format!("{base}/exchange"))
        .json(&json!({
            "account": ACCOUNT,
            "secret": SECRET,
            "product": PRODUCT,
            "hwid": vec![0u8; 32],
            "challenge": nonce,
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn mtls_rejects_clients_without_cert() {
    let ca = make_ca();
    let (addr, _server) = spawn_mtls_server(test_state(None), &ca).await;

    // Trusts the CA but presents no client cert: the handshake itself
    // must fail — this is a TLS-layer rejection, not an HTTP status.
    let client = http_client(&ca, None);
    let err = client
        .post(format!("https://{addr}/challenge"))
        .send()
        .await
        .expect_err("request without a client cert must fail at TLS");
    assert!(err.is_connect() || err.is_request(), "expected a TLS-layer failure, got {err}");
}

#[tokio::test]
async fn mtls_accepts_ca_issued_client_cert() {
    let ca = make_ca();
    let (cert_pem, key_pem, _sha) = issue_client_cert(&ca, ACCOUNT);
    let (addr, _server) = spawn_mtls_server(test_state(None), &ca).await;

    // No cert_sha256 pin on the account: any CA-issued cert
    // authenticates the install, and the exchange succeeds.
    let client = http_client(&ca, Some((&cert_pem, &key_pem)));
    let (status, _body) = exchange(&client, addr).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn cert_sha256_binding_rejects_wrong_cert() {
    let ca = make_ca();
    // The account is pinned to a cert the client does NOT hold.
    let (_pinned_pem, _pinned_key, pinned_sha) = issue_client_cert(&ca, ACCOUNT);
    // The client presents a different, still CA-issued cert — valid
    // mTLS, wrong binding.
    let (other_pem, other_key, _other_sha) = issue_client_cert(&ca, ACCOUNT);
    let (addr, _server) =
        spawn_mtls_server(test_state(Some((ACCOUNT, pinned_sha))), &ca).await;

    let client = http_client(&ca, Some((&other_pem, &other_key)));
    let (status, body) = exchange(&client, addr).await;
    // Identical to bad credentials — the response must never confirm
    // the secret was right.
    assert_eq!(status, 401, "expected 401, got {status}: {body}");
    assert_eq!(body["error"], "invalid credentials");
}

#[tokio::test]
async fn cert_sha256_binding_accepts_pinned_cert() {
    let ca = make_ca();
    let (cert_pem, key_pem, sha) = issue_client_cert(&ca, ACCOUNT);
    let (addr, _server) = spawn_mtls_server(test_state(Some((ACCOUNT, sha))), &ca).await;

    let client = http_client(&ca, Some((&cert_pem, &key_pem)));
    let (status, body) = exchange(&client, addr).await;
    assert_eq!(status, 200, "expected 200, got {status}: {body}");
}

#[tokio::test]
async fn cert_sha256_binding_rejects_cn_mismatch() {
    let ca = make_ca();
    // Pinned hash matches the presented cert, but its CN names a
    // different account — the CN check is what stops a cert issued
    // for "mallory" from standing in for "dev".
    let (cert_pem, key_pem, sha) = issue_client_cert(&ca, "mallory");
    let (addr, _server) = spawn_mtls_server(test_state(Some((ACCOUNT, sha))), &ca).await;

    let client = http_client(&ca, Some((&cert_pem, &key_pem)));
    let (status, body) = exchange(&client, addr).await;
    assert_eq!(status, 401, "expected 401, got {status}: {body}");
    assert_eq!(body["error"], "invalid credentials");
}

/// A client cert from a DIFFERENT CA must die at the TLS handshake —
/// before any handler runs. This is the transport boundary, not a 403.
#[tokio::test]
async fn mtls_rejects_client_cert_from_foreign_ca() {
    let ca = make_ca();
    let rogue_ca = make_ca();
    // Well-formed client cert, wrong issuer entirely.
    let (rogue_pem, rogue_key, _sha) = issue_client_cert(&rogue_ca, ACCOUNT);
    let (addr, _server) = spawn_mtls_server(test_state(None), &ca).await;

    let client = http_client(&ca, Some((&rogue_pem, &rogue_key)));
    let err = client
        .post(format!("https://{addr}/challenge"))
        .send()
        .await
        .expect_err("a foreign-CA client cert must fail the handshake");
    assert!(
        err.is_connect() || err.is_request(),
        "expected a TLS-layer failure, got {err}"
    );
}

/// An expired client cert must fail the handshake even when the right
/// CA signed it — validity windows are part of chain verification.
#[tokio::test]
async fn mtls_rejects_expired_client_cert() {
    let ca = make_ca();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ACCOUNT);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2020, 1, 2);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();
    let (addr, _server) = spawn_mtls_server(test_state(None), &ca).await;

    let client = http_client(&ca, Some((&cert_pem, &key_pem)));
    let err = client
        .post(format!("https://{addr}/challenge"))
        .send()
        .await
        .expect_err("an expired client cert must fail the handshake");
    assert!(
        err.is_connect() || err.is_request(),
        "expected a TLS-layer failure, got {err}"
    );
}

// ---- subject_common_name DER walk -----------------------------------

/// Build one DER TLV (short-form length — every test value is < 128B).
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    assert!(content.len() < 128);
    let mut v = vec![tag, content.len() as u8];
    v.extend_from_slice(content);
    v
}

/// An RDN (SET OF AttributeTypeAndValue) holding one CN attribute with
/// the given string tag.
fn cn_rdn(value_tag: u8, cn: &[u8]) -> Vec<u8> {
    let mut atv = tlv(0x06, &[0x55, 0x04, 0x03]); // id-at-commonName
    atv.extend_from_slice(&tlv(value_tag, cn));
    tlv(0x31, &tlv(0x30, &atv))
}

/// An RDN for a non-CN attribute (O = 2.5.4.10, UTF8String).
fn org_rdn(name: &str) -> Vec<u8> {
    let mut atv = tlv(0x06, &[0x55, 0x04, 0x0a]);
    atv.extend_from_slice(&tlv(0x0c, name.as_bytes()));
    tlv(0x31, &tlv(0x30, &atv))
}

#[test]
fn cn_parses_utf8_and_wrapped_forms() {
    use keystone_server::tls::subject_common_name;
    // webpki hands back the Name's contents — bare RDNs.
    let bare = cn_rdn(0x0c, b"dev");
    assert_eq!(subject_common_name(&bare).as_deref(), Some("dev"));
    // The same Name wrapped in its outer SEQUENCE must also parse.
    let wrapped = tlv(0x30, &bare);
    assert_eq!(subject_common_name(&wrapped).as_deref(), Some("dev"));
    // PrintableString and IA5String decode identically.
    assert_eq!(
        subject_common_name(&cn_rdn(0x13, b"dev")).as_deref(),
        Some("dev")
    );
    assert_eq!(
        subject_common_name(&cn_rdn(0x16, b"dev")).as_deref(),
        Some("dev")
    );
}

#[test]
fn cn_parses_bmpstring() {
    use keystone_server::tls::subject_common_name;
    // BMPString is UTF-16BE: "dev" = 00 64 00 65 00 76.
    let bmp: &[u8] = &[0x00, 0x64, 0x00, 0x65, 0x00, 0x76];
    assert_eq!(
        subject_common_name(&cn_rdn(0x1e, bmp)).as_deref(),
        Some("dev")
    );
}

#[test]
fn cn_found_among_other_rdns() {
    use keystone_server::tls::subject_common_name;
    // CN after other attributes — real certs order O/C/OU first.
    let mut name = org_rdn("example-org");
    name.extend_from_slice(&cn_rdn(0x0c, b"dev"));
    assert_eq!(subject_common_name(&name).as_deref(), Some("dev"));

    // Multi-valued RDN: one SET carrying O and CN together.
    let mut atvs = {
        let mut atv = tlv(0x06, &[0x55, 0x04, 0x0a]);
        atv.extend_from_slice(&tlv(0x0c, b"example-org"));
        tlv(0x30, &atv)
    };
    let mut cn_atv = tlv(0x06, &[0x55, 0x04, 0x03]);
    cn_atv.extend_from_slice(&tlv(0x0c, b"dev"));
    atvs.extend_from_slice(&tlv(0x30, &cn_atv));
    let rdn = tlv(0x31, &atvs);
    assert_eq!(subject_common_name(&rdn).as_deref(), Some("dev"));
}

#[test]
fn cn_malformed_der_returns_none() {
    use keystone_server::tls::subject_common_name;
    assert_eq!(subject_common_name(&[]), None);
    assert_eq!(subject_common_name(&[0x30]), None); // truncated TLV
    assert_eq!(subject_common_name(&[0x30, 0x7f, 0x01]), None); // overlong
    assert_eq!(subject_common_name(&[0xff, 0xff, 0xff]), None);
    // A wrapped SEQUENCE whose tail is garbage must not parse.
    let mut bad = tlv(0x30, &cn_rdn(0x0c, b"dev"));
    bad.push(0x00);
    assert_eq!(subject_common_name(&bad), None);
    // A name with no CN RDN at all.
    assert_eq!(subject_common_name(&org_rdn("example-org")), None);
    // CN OID carrying an undecodable string type (OCTET STRING).
    assert_eq!(subject_common_name(&cn_rdn(0x04, b"dev")), None);
}
