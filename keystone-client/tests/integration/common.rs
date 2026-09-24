//! Shared rig: a keystone server built with `AppState::builder`, served
//! over mTLS by `keystone_server::serve`, and the client material to reach it.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::Router;
use chrono::{Duration, Utc};
use keystone_client::{
    AdminClient, ClientBuilder, ClientIdentity, ClientSession, KeystoneClient, TrustedIssuers,
};
use keystone_core::{
    AccountIdentity, BackendError, Entitlement, EntitlementSource, Issuer, KEYFILE_LEN,
};
use keystone_server::{AdminToken, AppState, AppStateBuilder, Listeners, serve};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

pub const ACCOUNT: &str = "dev";
pub const SECRET: &str = "devpass";
pub const PRODUCT: &str = "dev-product";
pub const OTHER_PRODUCT: &str = "other-product";
pub const PROCESS_ID: &str = "app.exe";
pub const ADMIN_TOKEN: &str = "0123456789abcdef0123456789abcdef-admin";
pub const HWID: [u8; 32] = [7; 32];
pub const SERVER_SANS: &[&str] = &["localhost", "127.0.0.1"];

/// A 30-day grant of `product` to [`ACCOUNT`].
pub fn grant(product: &str, features: &[&str]) -> Entitlement {
    Entitlement {
        account: ACCOUNT.to_owned(),
        product: product.to_owned(),
        expires_at: Utc::now() + Duration::days(30),
        features: features.iter().map(|f| f.to_string()).collect(),
    }
}

/// One account ([`ACCOUNT`]/[`SECRET`]) whose grants tests can change, and
/// a count of every login attempt that reached the backend.
pub struct TestSource {
    grants: RwLock<Vec<Entitlement>>,
    logins: AtomicUsize,
}

impl TestSource {
    pub fn with_grants(grants: Vec<Entitlement>) -> Arc<Self> {
        Arc::new(Self {
            grants: RwLock::new(grants),
            logins: AtomicUsize::new(0),
        })
    }

    /// [`PRODUCT`] with feature `all`.
    pub fn standard() -> Arc<Self> {
        Self::with_grants(vec![grant(PRODUCT, &["all"])])
    }

    pub fn set_grants(&self, grants: Vec<Entitlement>) {
        *self.grants.write() = grants;
    }

    pub fn logins(&self) -> usize {
        self.logins.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl EntitlementSource for TestSource {
    async fn authenticate(
        &self,
        account: &str,
        secret: &str,
    ) -> Result<Option<AccountIdentity>, BackendError> {
        self.logins.fetch_add(1, Ordering::SeqCst);
        Ok(
            (account == ACCOUNT && secret == SECRET).then(|| AccountIdentity {
                account: account.to_owned(),
            }),
        )
    }

    async fn entitlement(
        &self,
        account: &str,
        product: &str,
    ) -> Result<Option<Entitlement>, BackendError> {
        if account != ACCOUNT {
            return Ok(None);
        }
        let grants = self.grants.read();
        Ok(grants.iter().find(|g| g.product == product).cloned())
    }
}

pub struct TestCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

/// A server leaf: PEMs plus the sha256 of its SubjectPublicKeyInfo.
pub struct ServerCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub spki_sha256: [u8; 32],
}

/// A client leaf: PEMs plus the sha256 of its DER encoding.
pub struct ClientCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub sha256: [u8; 32],
}

pub fn make_ca() -> TestCa {
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

impl TestCa {
    pub fn pem(&self) -> String {
        self.cert.pem()
    }

    /// A server leaf for `sans` under a fresh key.
    pub fn server_cert(&self, sans: &[&str]) -> ServerCert {
        let names = sans.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            sans.first().copied().unwrap_or("server"),
        );
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        ServerCert {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            spki_sha256: Sha256::digest(key.public_key_der()).into(),
        }
    }

    /// A client leaf with common name `cn`.
    pub fn client_cert(&self, cn: &str) -> ClientCert {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.cert, &self.key).unwrap();
        ClientCert {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            sha256: Sha256::digest(cert.der()).into(),
        }
    }
}

/// A running `serve`; dropping it shuts the server down.
pub struct Server {
    pub public: SocketAddr,
    pub admin: SocketAddr,
    _shutdown: oneshot::Sender<()>,
}

fn spawn_server(state: AppState, ca: &TestCa, cert: &ServerCert) -> Server {
    let tls = keystone_server::tls::load_rustls_config(
        cert.cert_pem.as_bytes(),
        cert.key_pem.as_bytes(),
        Some(ca.pem().as_bytes()),
    )
    .unwrap();
    let public = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let admin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listeners = Listeners::from_std(public, Some(admin), Some(tls)).unwrap();
    let public = listeners.public_addr();
    let admin = listeners.admin_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(serve(state, listeners, async move {
        let _ = rx.await;
    }));
    Server {
        public,
        admin,
        _shutdown: tx,
    }
}

/// Serve an arbitrary router over the same mTLS setup; returns its address.
pub fn serve_router(ca: &TestCa, router: Router) -> SocketAddr {
    let cert = ca.server_cert(SERVER_SANS);
    let tls = keystone_server::tls::load_rustls_config(
        cert.cert_pem.as_bytes(),
        cert.key_pem.as_bytes(),
        Some(ca.pem().as_bytes()),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(axum_server::from_tcp_rustls(listener, tls).serve(router.into_make_service()));
    addr
}

pub fn https_url(addr: SocketAddr) -> String {
    format!("https://{addr}")
}

/// A live server plus everything a client needs to talk to it.
pub struct Rig {
    pub ca: TestCa,
    pub source: Arc<TestSource>,
    pub issuers: TrustedIssuers,
    pub identity: ClientIdentity,
    pub server_spki: [u8; 32],
    pub server: Server,
    keyfile: Zeroizing<[u8; KEYFILE_LEN]>,
    identity_sha256: [u8; 32],
}

pub async fn rig() -> Rig {
    Rig::start(TestSource::standard(), SERVER_SANS, |b| b).await
}

pub async fn rig_with(configure: impl FnOnce(AppStateBuilder) -> AppStateBuilder) -> Rig {
    Rig::start(TestSource::standard(), SERVER_SANS, configure).await
}

/// State for an mTLS deployment whose admin allow-list holds the rig's
/// client certificate.
async fn build_state(
    keyfile: &[u8],
    source: Arc<TestSource>,
    admin_cert: [u8; 32],
    configure: impl FnOnce(AppStateBuilder) -> AppStateBuilder,
) -> AppState {
    let issuer = Issuer::from_keyfile(keyfile).unwrap();
    let builder = AppState::builder(issuer, source)
        .admin_token(AdminToken::new(ADMIN_TOKEN).unwrap())
        .require_client_certificates(true)
        .admin_certificates(BTreeSet::from([admin_cert]));
    configure(builder).build().await.expect("state builds")
}

impl Rig {
    /// A fresh issuer and CA, a server whose leaf covers `sans`, and a
    /// client identity for [`ACCOUNT`] that is also the admin certificate.
    pub async fn start(
        source: Arc<TestSource>,
        sans: &[&str],
        configure: impl FnOnce(AppStateBuilder) -> AppStateBuilder,
    ) -> Rig {
        let issuer = Issuer::generate(1);
        let keyfile = issuer.keyfile_bytes();
        let issuers = TrustedIssuers::single(issuer.key_id(), issuer.verifying_key());
        let ca = make_ca();
        let client = ca.client_cert(ACCOUNT);
        let identity = ClientIdentity::from_pem(client.cert_pem, client.key_pem);
        let state = build_state(&keyfile[..], source.clone(), client.sha256, configure).await;
        let cert = ca.server_cert(sans);
        let server = spawn_server(state, &ca, &cert);
        Rig {
            ca,
            source,
            issuers,
            identity,
            server_spki: cert.spki_sha256,
            server,
            keyfile,
            identity_sha256: client.sha256,
        }
    }

    /// Replace the server with one over the same signing key and backend
    /// but an empty session store.
    pub async fn restart(&mut self) {
        let state = build_state(
            &self.keyfile[..],
            self.source.clone(),
            self.identity_sha256,
            |b| b,
        )
        .await;
        let cert = self.ca.server_cert(SERVER_SANS);
        self.server = spawn_server(state, &self.ca, &cert);
        self.server_spki = cert.spki_sha256;
    }

    /// The issuer signing for this rig.
    pub fn issuer(&self) -> Issuer {
        Issuer::from_keyfile(&self.keyfile[..]).unwrap()
    }

    /// A builder for `addr` with the issuer set and the client identity,
    /// but no server trust configured.
    pub fn bare_builder(&self, addr: SocketAddr) -> ClientBuilder {
        KeystoneClient::builder(https_url(addr), self.issuers.clone())
            .identity(self.identity.clone())
    }

    pub fn client_for(&self, addr: SocketAddr) -> KeystoneClient {
        self.bare_builder(addr)
            .server_ca_pem(self.ca.pem())
            .build()
            .unwrap()
    }

    pub fn client(&self) -> KeystoneClient {
        self.client_for(self.server.public)
    }

    pub fn admin(&self) -> AdminClient {
        AdminClient::builder(https_url(self.server.admin))
            .server_ca_pem(self.ca.pem())
            .identity(self.identity.clone())
            .admin_token(ADMIN_TOKEN)
            .build()
            .unwrap()
    }

    pub async fn exchange(&self, client: &KeystoneClient) -> ClientSession {
        client
            .exchange(ACCOUNT, SECRET, PRODUCT, HWID)
            .await
            .expect("exchange succeeds")
    }
}
