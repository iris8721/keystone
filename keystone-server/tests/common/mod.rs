//! Shared harness: an in-memory entitlement source, a recording audit sink,
//! request builders that MAC exactly like a client, and a TLS rig that runs
//! the real `serve`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration, Utc};
use http_body_util::BodyExt;
use keystone_core::wire::{
    self, AUDIENCE_APP, AUDIENCE_CLIENT, AttestBody, AttestRequest, ErrorBody, ErrorCode,
    ExchangeBody, ExchangeRequest, HandoffBody, HandoffRequest, HeartbeatRequest, LeaseBody,
    OP_ATTEST, OP_EXCHANGE, OP_HANDOFF, OP_HEARTBEAT, PROTOCOL_HEADER, PayloadBody, PayloadRequest,
    mac_context,
};
use keystone_core::{
    AccountIdentity, BackendError, Challenge, Entitlement, EntitlementSource, Envelope,
    Expectation, Issuer, RequestBinding, TrustedIssuers, handoff_wrap_key, mac_request,
    unwrap_secret,
};
use keystone_server::{
    AppState, AppStateBuilder, AuditEvent, AuditSink, HandoffRecord, Listeners, MemoryStore,
    SessionRecord, SessionStore, admin_router, public_router, serve,
};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const ACCOUNT: &str = "dev";
pub const SECRET: &str = "devpass";
pub const PRODUCT: &str = "dev-product";
pub const OTHER_PRODUCT: &str = "other-product";
pub const PROCESS_ID: &str = "app.exe";
pub const ADMIN_TOKEN: &str = "0123456789abcdef0123456789abcdef-admin";

pub fn grant(product: &str, expires_at: DateTime<Utc>, features: &[&str]) -> Entitlement {
    Entitlement {
        account: ACCOUNT.to_string(),
        product: product.to_string(),
        expires_at,
        features: features.iter().map(|f| f.to_string()).collect(),
    }
}

struct Account {
    secret: String,
    grants: Vec<Entitlement>,
    pin: Option<[u8; 32]>,
}

/// Plain-comparison entitlement source whose grants and pins tests can
/// change mid-session, which can simulate an outage, and which counts
/// password checks.
#[derive(Default)]
pub struct TestSource {
    accounts: RwLock<HashMap<String, Account>>,
    down: AtomicBool,
    authentications: AtomicUsize,
}

impl TestSource {
    /// `dev`/`devpass` with 30 days of `dev-product` (feature `all`).
    pub fn standard() -> Arc<Self> {
        let source = Self::default();
        source.add(
            ACCOUNT,
            SECRET,
            vec![grant(PRODUCT, Utc::now() + Duration::days(30), &["all"])],
        );
        Arc::new(source)
    }

    pub fn add(&self, account: &str, secret: &str, grants: Vec<Entitlement>) {
        self.accounts.write().insert(
            account.to_string(),
            Account {
                secret: secret.to_string(),
                grants,
                pin: None,
            },
        );
    }

    pub fn set_grants(&self, account: &str, grants: Vec<Entitlement>) {
        self.accounts.write().get_mut(account).unwrap().grants = grants;
    }

    pub fn pin(&self, account: &str, cert_sha256: [u8; 32]) {
        self.accounts.write().get_mut(account).unwrap().pin = Some(cert_sha256);
    }

    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }

    /// How many times `authenticate` ran.
    pub fn authentications(&self) -> usize {
        self.authentications.load(Ordering::SeqCst)
    }

    fn check_up(&self) -> Result<(), BackendError> {
        if self.down.load(Ordering::SeqCst) {
            Err("backend down".into())
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl EntitlementSource for TestSource {
    async fn authenticate(
        &self,
        account: &str,
        secret: &str,
    ) -> Result<Option<AccountIdentity>, BackendError> {
        self.check_up()?;
        self.authentications.fetch_add(1, Ordering::SeqCst);
        // Long enough that concurrent attempts overlap, as argon2 would.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let accounts = self.accounts.read();
        Ok(accounts
            .get(account)
            .filter(|a| a.secret == secret)
            .map(|_| AccountIdentity {
                account: account.to_string(),
            }))
    }

    async fn entitlement(
        &self,
        account: &str,
        product: &str,
    ) -> Result<Option<Entitlement>, BackendError> {
        self.check_up()?;
        let accounts = self.accounts.read();
        Ok(accounts
            .get(account)
            .and_then(|a| a.grants.iter().find(|g| g.product == product).cloned()))
    }

    async fn cert_sha256(&self, account: &str) -> Result<Option<[u8; 32]>, BackendError> {
        self.check_up()?;
        Ok(self.accounts.read().get(account).and_then(|a| a.pin))
    }
}

/// Audit sink that keeps every event.
#[derive(Default)]
pub struct RecordingAudit(Mutex<Vec<AuditEvent>>);

impl RecordingAudit {
    pub fn events(&self) -> Vec<AuditEvent> {
        self.0.lock().clone()
    }
}

impl AuditSink for RecordingAudit {
    fn record(&self, event: AuditEvent) {
        self.0.lock().push(event);
    }
}

/// A state plus its router and the handles tests inspect.
pub struct Harness {
    pub state: AppState,
    pub app: Router,
    pub issuers: TrustedIssuers,
    pub source: Arc<TestSource>,
    pub store: Arc<MemoryStore>,
    pub audit: Arc<RecordingAudit>,
    pub keyfile: Zeroizing<[u8; keystone_core::KEYFILE_LEN]>,
}

pub async fn harness() -> Harness {
    harness_with(TestSource::standard(), |b| b).await
}

pub async fn harness_with(
    source: Arc<TestSource>,
    configure: impl FnOnce(AppStateBuilder) -> AppStateBuilder,
) -> Harness {
    let issuer = Issuer::generate(1);
    let keyfile = issuer.keyfile_bytes();
    let issuers = TrustedIssuers::single(issuer.key_id(), issuer.verifying_key());
    let store = Arc::new(MemoryStore::new());
    let audit = Arc::new(RecordingAudit::default());
    let builder = AppState::builder(issuer, source.clone())
        .session_store(store.clone())
        .audit(audit.clone());
    let state = configure(builder).build().await.expect("state builds");
    Harness {
        app: with_peer(public_router(state.clone()), PEER),
        state,
        issuers,
        source,
        store,
        audit,
        keyfile,
    }
}

impl Harness {
    /// The admin router as seen from [`PEER`].
    pub fn admin_app(&self) -> Router {
        with_peer(admin_router(self.state.clone()), PEER)
    }

    /// The stored record of a session that must exist.
    pub async fn store_record(&self, id: Uuid) -> (keystone_server::SessionRecord, u64) {
        keystone_server::SessionStore::get(self.store.as_ref(), &id)
            .await
            .unwrap()
            .expect("session stored")
    }

    /// The same signing key over a fresh, empty session store: a restart.
    pub async fn restarted(&self) -> Harness {
        let issuer = Issuer::from_keyfile(&self.keyfile[..]).unwrap();
        let store = Arc::new(MemoryStore::new());
        let audit = Arc::new(RecordingAudit::default());
        let state = AppState::builder(issuer, self.source.clone())
            .session_store(store.clone())
            .audit(audit.clone())
            .build()
            .await
            .unwrap();
        Harness {
            app: with_peer(public_router(state.clone()), PEER),
            state,
            issuers: self.issuers.clone(),
            source: self.source.clone(),
            store,
            audit,
            keyfile: self.keyfile.clone(),
        }
    }
}

pub fn nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut n);
    n
}

/// Default client address for in-process requests.
pub const PEER: &str = "192.0.2.10:40000";

/// `router` serving requests as if they arrived from `addr`.
pub fn with_peer(router: Router, addr: &str) -> Router {
    let addr: SocketAddr = addr.parse().unwrap();
    router.layer(MockConnectInfo(addr))
}

/// A `MemoryStore` with switchable faults that reproduce races
/// deterministically: bumping an account's revocation epoch during an
/// insert, and account/key snapshots that miss child sessions.
#[derive(Default)]
pub struct HookStore {
    pub inner: MemoryStore,
    pub bump_epoch_on_insert: AtomicBool,
    pub hide_children_from_snapshots: AtomicBool,
}

impl HookStore {
    async fn roots_only(&self, ids: Vec<Uuid>) -> Result<Vec<Uuid>, BackendError> {
        if !self.hide_children_from_snapshots.load(Ordering::SeqCst) {
            return Ok(ids);
        }
        let mut roots = Vec::new();
        for id in ids {
            if let Some((record, _)) = self.inner.get(&id).await?
                && record.parent.is_none()
            {
                roots.push(id);
            }
        }
        Ok(roots)
    }
}

#[async_trait]
impl SessionStore for HookStore {
    async fn insert(&self, record: SessionRecord) -> Result<(), BackendError> {
        if self.bump_epoch_on_insert.load(Ordering::SeqCst) {
            self.inner.bump_account_epoch(&record.account).await?;
        }
        self.inner.insert(record).await
    }

    async fn get(&self, id: &Uuid) -> Result<Option<(SessionRecord, u64)>, BackendError> {
        self.inner.get(id).await
    }

    async fn replace(
        &self,
        id: &Uuid,
        expected_version: u64,
        record: SessionRecord,
    ) -> Result<bool, BackendError> {
        self.inner.replace(id, expected_version, record).await
    }

    async fn ids_for_account(&self, account: &str) -> Result<Vec<Uuid>, BackendError> {
        let ids = self.inner.ids_for_account(account).await?;
        self.roots_only(ids).await
    }

    async fn children_of(&self, parent: &Uuid) -> Result<Vec<Uuid>, BackendError> {
        self.inner.children_of(parent).await
    }

    async fn all_ids(&self) -> Result<Vec<Uuid>, BackendError> {
        let ids = self.inner.all_ids().await?;
        self.roots_only(ids).await
    }

    async fn consume_nonce(
        &self,
        session_id: &Uuid,
        nonce: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<bool, BackendError> {
        self.inner
            .consume_nonce(session_id, nonce, expires_at)
            .await
    }

    async fn insert_handoff(
        &self,
        record: HandoffRecord,
        max_per_parent: usize,
    ) -> Result<bool, BackendError> {
        self.inner.insert_handoff(record, max_per_parent).await
    }

    async fn take_handoff(
        &self,
        handoff_id: &[u8; 32],
    ) -> Result<Option<HandoffRecord>, BackendError> {
        self.inner.take_handoff(handoff_id).await
    }

    async fn account_epoch(&self, account: &str) -> Result<u64, BackendError> {
        self.inner.account_epoch(account).await
    }

    async fn bump_account_epoch(&self, account: &str) -> Result<(), BackendError> {
        self.inner.bump_account_epoch(account).await
    }

    async fn sweep(&self, now: DateTime<Utc>) -> Result<usize, BackendError> {
        self.inner.sweep(now).await
    }
}

/// Send `req` through `app`; returns status and raw body.
pub async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, body)
}

/// POST JSON with the protocol header.
pub async fn post(app: &Router, path: &str, body: &impl Serialize) -> (StatusCode, Value) {
    let req = Request::post(path)
        .header("content-type", "application/json")
        .header(PROTOCOL_HEADER, wire::PROTOCOL_VERSION.to_string())
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let (status, bytes) = send(app, req).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// GET with the protocol header and an optional Authorization value.
pub async fn get(app: &Router, path: &str, authorization: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut req = Request::get(path).header(PROTOCOL_HEADER, wire::PROTOCOL_VERSION.to_string());
    if let Some(auth) = authorization {
        req = req.header("authorization", auth);
    }
    send(app, req.body(Body::empty()).unwrap()).await
}

/// The wire code of an error response; panics on anything but an ErrorBody.
pub fn code(body: &Value) -> ErrorCode {
    serde_json::from_value::<ErrorBody>(body.clone())
        .unwrap_or_else(|_| panic!("not an ErrorBody: {body}"))
        .code
}

pub fn code_bytes(body: &[u8]) -> ErrorCode {
    serde_json::from_slice::<ErrorBody>(body)
        .unwrap_or_else(|_| panic!("not an ErrorBody: {}", String::from_utf8_lossy(body)))
        .code
}

/// Verify an envelope's signature and scope, then decode its body.
pub fn open<B: DeserializeOwned>(
    issuers: &TrustedIssuers,
    value: &Value,
    challenge: [u8; 32],
    session_id: Option<Uuid>,
    audience: &str,
    operation: &str,
) -> (Envelope, B) {
    let env: Envelope = serde_json::from_value(value.clone()).expect("envelope");
    let body: B = serde_json::from_slice(&env.body).expect("envelope body");
    let challenge = Challenge {
        nonce: challenge,
        minted: Instant::now(),
    };
    env.verify(
        issuers,
        &Expectation {
            challenge: &challenge,
            session_id: &session_id.unwrap_or(env.session_id),
            audience,
            operation,
            now: Utc::now(),
        },
    )
    .expect("envelope verifies");
    (env, body)
}

#[derive(Clone)]
pub struct Session {
    pub id: Uuid,
    pub key: [u8; 32],
}

pub fn exchange_req(account: &str, secret: &str, product: &str) -> ExchangeRequest {
    ExchangeRequest {
        account: account.to_string(),
        secret: Zeroizing::new(secret.to_string()),
        product: product.to_string(),
        hwid: [3u8; 32],
        challenge: nonce(),
    }
}

/// Exchange `req`; asserts success and returns the session with its body.
pub async fn exchange_with(h: &Harness, req: ExchangeRequest) -> (Session, ExchangeBody) {
    let (status, value) = post(&h.app, "/exchange", &req).await;
    assert_eq!(status, StatusCode::OK, "exchange failed: {value}");
    let (_, body): (_, ExchangeBody) = open(
        &h.issuers,
        &value,
        req.challenge,
        None,
        AUDIENCE_CLIENT,
        OP_EXCHANGE,
    );
    (
        Session {
            id: body.session_id,
            key: *body.session_key,
        },
        body,
    )
}

pub async fn exchange(h: &Harness) -> Session {
    exchange_with(h, exchange_req(ACCOUNT, SECRET, PRODUCT))
        .await
        .0
}

fn mac(
    key: &[u8; 32],
    session_id: &Uuid,
    nonce: &[u8; 32],
    issued_at: DateTime<Utc>,
    context: &[u8],
) -> [u8; 32] {
    mac_request(
        key,
        &RequestBinding {
            session_id,
            nonce,
            issued_at,
            context,
        },
    )
}

/// Current time at wire (millisecond) precision.
pub fn now_ms() -> DateTime<Utc> {
    DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap()
}

pub fn heartbeat_req(
    session: &Session,
    nonce: [u8; 32],
    issued_at: DateTime<Utc>,
) -> HeartbeatRequest {
    HeartbeatRequest {
        session_id: session.id,
        nonce,
        issued_at,
        mac: mac(
            &session.key,
            &session.id,
            &nonce,
            issued_at,
            &mac_context::heartbeat(),
        ),
    }
}

/// Heartbeat with a fresh nonce; returns status and response.
pub async fn heartbeat(h: &Harness, session: &Session) -> (StatusCode, Value) {
    post(
        &h.app,
        "/heartbeat",
        &heartbeat_req(session, nonce(), now_ms()),
    )
    .await
}

/// Heartbeat that must succeed; returns the verified lease body.
pub async fn heartbeat_ok(h: &Harness, session: &Session) -> LeaseBody {
    let req = heartbeat_req(session, nonce(), now_ms());
    let (status, value) = post(&h.app, "/heartbeat", &req).await;
    assert_eq!(status, StatusCode::OK, "heartbeat failed: {value}");
    open(
        &h.issuers,
        &value,
        req.nonce,
        Some(session.id),
        AUDIENCE_CLIENT,
        OP_HEARTBEAT,
    )
    .1
}

pub fn handoff_req(session: &Session, process_id: &str, ttl_millis: u64) -> HandoffRequest {
    let nonce = nonce();
    let issued_at = now_ms();
    HandoffRequest {
        session_id: session.id,
        nonce,
        issued_at,
        process_id: process_id.to_string(),
        ttl_millis,
        mac: mac(
            &session.key,
            &session.id,
            &nonce,
            issued_at,
            &mac_context::handoff(process_id, ttl_millis),
        ),
    }
}

/// Mint a handoff that must succeed.
pub async fn handoff_ok(app: &Router, issuers: &TrustedIssuers, session: &Session) -> HandoffBody {
    let req = handoff_req(session, PROCESS_ID, 60_000);
    let (status, value) = post(app, "/handoff", &req).await;
    assert_eq!(status, StatusCode::OK, "handoff failed: {value}");
    open(
        issuers,
        &value,
        req.nonce,
        Some(session.id),
        AUDIENCE_CLIENT,
        OP_HANDOFF,
    )
    .1
}

pub fn attest_req(parent: &Uuid, handoff: &HandoffBody, process_id: &str) -> AttestRequest {
    attest_req_with(
        parent,
        &handoff.handoff_id,
        &handoff.handoff_secret,
        process_id,
    )
}

pub fn attest_req_with(
    parent: &Uuid,
    handoff_id: &[u8; 32],
    secret: &[u8; 32],
    process_id: &str,
) -> AttestRequest {
    let challenge = nonce();
    let issued_at = now_ms();
    AttestRequest {
        parent_session_id: *parent,
        handoff_id: *handoff_id,
        challenge,
        issued_at,
        process_id: process_id.to_string(),
        mac: mac(
            secret,
            parent,
            &challenge,
            issued_at,
            &mac_context::attest(handoff_id, process_id),
        ),
    }
}

/// Redeem a handoff that must succeed; returns the child session.
pub async fn attest_ok(
    app: &Router,
    issuers: &TrustedIssuers,
    parent: &Uuid,
    handoff: &HandoffBody,
) -> (Session, AttestBody) {
    let req = attest_req(parent, handoff, PROCESS_ID);
    let (status, value) = post(app, "/attest", &req).await;
    assert_eq!(status, StatusCode::OK, "attest failed: {value}");
    let (env, body): (_, AttestBody) = open(
        issuers,
        &value,
        req.challenge,
        None,
        AUDIENCE_APP,
        OP_ATTEST,
    );
    assert_eq!(env.session_id, body.session_id);
    let wrap_key = handoff_wrap_key(&handoff.handoff_secret, &req.challenge);
    let key = unwrap_secret(&wrap_key, &body.session_key_wrap).expect("child key unwraps");
    (
        Session {
            id: body.session_id,
            key: *key,
        },
        body,
    )
}

pub fn payload_req(session: &Session, product: &str, version: &str) -> PayloadRequest {
    let nonce = nonce();
    let issued_at = now_ms();
    PayloadRequest {
        session_id: session.id,
        product: product.to_string(),
        version: version.to_string(),
        nonce,
        issued_at,
        mac: mac(
            &session.key,
            &session.id,
            &nonce,
            issued_at,
            &mac_context::payload(product, version),
        ),
    }
}

/// `Authorization` value for `GET /payload/{product}/{version}`.
pub fn download_auth(session: &Session, product: &str, version: &str) -> String {
    let nonce = nonce();
    let issued_at = now_ms();
    wire::DownloadAuthorization {
        session_id: session.id,
        nonce,
        issued_at,
        mac: mac(
            &session.key,
            &session.id,
            &nonce,
            issued_at,
            &mac_context::download(product, version),
        ),
    }
    .encode()
}

pub fn open_payload(issuers: &TrustedIssuers, value: &Value, req: &PayloadRequest) -> PayloadBody {
    open(
        issuers,
        value,
        req.nonce,
        Some(req.session_id),
        AUDIENCE_APP,
        wire::OP_PAYLOAD_FETCH,
    )
    .1
}

pub fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("keystone-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---- TLS rig ----

pub struct TestCa {
    pub cert: rcgen::Certificate,
    key: rcgen::KeyPair,
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

/// A client identity: PEM bundle for reqwest plus the leaf DER sha256.
pub struct ClientCert {
    pub bundle: String,
    pub sha256: [u8; 32],
}

pub fn client_cert(ca: &TestCa, cn: &str) -> ClientCert {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    ClientCert {
        bundle: format!("{}{}", cert.pem(), key.serialize_pem()),
        sha256: Sha256::digest(cert.der().as_ref()).into(),
    }
}

fn server_cert(ca: &TestCa) -> (String, String) {
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

/// A running `serve` over mTLS on ephemeral ports.
pub struct TlsServer {
    pub public: SocketAddr,
    pub admin: Option<SocketAddr>,
    pub shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    pub task: tokio::task::JoinHandle<Result<(), keystone_server::ServerError>>,
}

pub fn spawn_mtls(state: AppState, ca: &TestCa, with_admin: bool) -> TlsServer {
    let (cert_pem, key_pem) = server_cert(ca);
    let tls = keystone_server::tls::load_rustls_config(
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
        Some(ca.cert.pem().as_bytes()),
    )
    .unwrap();
    let public = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let admin = with_admin.then(|| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
    let listeners = Listeners::from_std(public, admin, Some(tls)).unwrap();
    let public = listeners.public_addr();
    let admin = listeners.admin_addr();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(serve(state, listeners, async move {
        let _ = rx.await;
    }));
    TlsServer {
        public,
        admin,
        shutdown: Some(tx),
        task,
    }
}

/// HTTPS client trusting only the test CA, optionally presenting `identity`.
pub fn https_client(ca: &TestCa, identity: Option<&ClientCert>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.cert.pem().as_bytes()).unwrap());
    if let Some(identity) = identity {
        builder =
            builder.identity(reqwest::Identity::from_pem(identity.bundle.as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

/// POST JSON over HTTPS with the protocol header.
pub async fn https_post(
    client: &reqwest::Client,
    addr: SocketAddr,
    path: &str,
    body: &impl Serialize,
) -> (u16, Value) {
    let resp = client
        .post(format!("https://{addr}{path}"))
        .header(PROTOCOL_HEADER, wire::PROTOCOL_VERSION.to_string())
        .json(body)
        .send()
        .await
        .expect("request reaches the server");
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}
