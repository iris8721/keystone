//! `KeystoneClient` — the SDK surface loaders and payloads link against.
//!
//! The client is never the authority (README): it collects
//! credentials, proves session-key possession, and verifies that every
//! grant it accepts was signed by an issuer key in the trusted set
//! baked into the build. Anything that fails verification is treated
//! as if it never arrived. The set only ever shrinks at runtime: the
//! server announces revoked key ids inside signed bodies, and the
//! client stops trusting them on the spot.

use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use keystone_core::{
    Challenge, DeadReason, Envelope, Expectation, KeyWrap, KeystoneError, Lease,
    MAX_ARTIFACT_BYTES, Manifest, RequestBinding, SessionState, SignedManifest, TrustedIssuers,
    artifact_context, decrypt_artifact, mac_request, unwrap_artifact_key,
};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ClientError;
use crate::session::ClientSession;

/// Envelope audiences — must match routes.rs exactly. A grant minted
/// for the client must not verify as a grant to the application.
const AUDIENCE_CLIENT: &str = "keystone-client";
const AUDIENCE_APP: &str = "keystone-app";

const OP_EXCHANGE: &str = "session.exchange";
const OP_ATTEST: &str = "session.attest";
const OP_HEARTBEAT: &str = "session.heartbeat";
const OP_PAYLOAD_FETCH: &str = "payload.fetch";

/// Epoch used in the artifact context the payload MACs bind. The MAC
/// binds product+version for a request; the real payload epoch is a
/// server-side key-derivation input the client never learns before
/// the manifest arrives, so both sides fix it at 0 here. Must match
/// routes.rs exactly.
const MAC_CONTEXT_EPOCH: u32 = 0;

/// Server error codes that mean "transient, not a verdict" — the
/// session survives these. Must match routes.rs exactly.
const CODE_ARTIFACT_NOT_FOUND: &str = "artifact_not_found";
const CODE_SESSION_NOT_ACTIVE: &str = "session_not_active";
const CODE_RATE_LIMITED: &str = "rate_limited";
const CODE_STALE_REQUEST: &str = "stale_request";

/// How long the client will accept a response to a challenge it
/// minted. The verifier issues the nonce (README: "bound to a
/// challenge/nonce the verifier issued"), so the verifier also owns
/// the window in which the echo is still fresh. Well above
/// `REQUEST_TIMEOUT`, so only a clock jump mid-request trips it.
const CHALLENGE_TTL_SECS: i64 = 60;

/// Hard cap on any single request. Bounded well under any sane
/// lease_ttl so a blackholed connection surfaces as a transient
/// failure — and the grace clock starts — instead of hanging the
/// caller past the point where the lease was already dead.
const REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(10);

/// Client for the keystone-server authorization surface.
///
/// `issuers` is the whole point: the client trusts exactly the issuer
/// keys baked into the build. No CA, no "trusted" third party, no key
/// learned from the network — an envelope that doesn't verify against
/// a live key in this set is garbage. The set is shared by every
/// clone so a revocation learned on one session applies to all.
#[derive(Clone)]
pub struct KeystoneClient {
    http: reqwest::Client,
    base_url: String,
    issuers: Arc<RwLock<TrustedIssuers>>,
}

/// A client certificate chain + private key for mTLS, both PEM.
/// Issued per-account by `cargo xtask issue-cert` (CN = account name).
#[derive(Clone)]
pub struct ClientIdentity {
    /// PEM certificate chain, leaf first.
    pub cert_pem: Vec<u8>,
    /// PEM private key (PKCS#8).
    pub key_pem: Vec<u8>,
}

/// What `new_pinned` needs to build the rustls config: the keystone
/// CA as the sole trust root, the server SPKI pin, and an optional
/// client identity.
struct PinnedTls {
    ca_cert_pem: Vec<u8>,
    server_spki_sha256: [u8; 32],
    identity: Option<ClientIdentity>,
}

impl PinnedTls {
    fn client_config(&self) -> Result<rustls::ClientConfig, ClientError> {
        let mut roots = RootCertStore::empty();
        let mut found = false;
        for cert in rustls_pemfile::certs(&mut &self.ca_cert_pem[..]) {
            let cert = cert.map_err(|e| ClientError::Tls(format!("CA cert PEM: {e}")))?;
            roots
                .add(cert)
                .map_err(|e| ClientError::Tls(format!("CA cert: {e}")))?;
            found = true;
        }
        if !found {
            return Err(ClientError::Tls(
                "no certificates in CA cert PEM".to_string(),
            ));
        }

        // Explicit provider: the workspace enables both ring and
        // aws-lc-rs on rustls (via reqwest and axum-server), so the
        // crate-feature default is ambiguous and `builder()` would
        // panic.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| ClientError::Tls(format!("server verifier: {e}")))?;
        let verifier = SpkiPinVerifier {
            inner: webpki,
            pin: self.server_spki_sha256,
        };

        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ClientError::Tls(format!("protocol versions: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier));
        match &self.identity {
            Some(id) => {
                let certs: Vec<CertificateDer<'static>> =
                    rustls_pemfile::certs(&mut &id.cert_pem[..])
                        .collect::<Result<_, _>>()
                        .map_err(|e| ClientError::Tls(format!("client cert PEM: {e}")))?;
                if certs.is_empty() {
                    return Err(ClientError::Tls(
                        "no certificates in client cert PEM".to_string(),
                    ));
                }
                let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &id.key_pem[..])
                    .map_err(|e| ClientError::Tls(format!("client key PEM: {e}")))?
                    .ok_or_else(|| {
                        ClientError::Tls("no private key in client key PEM".to_string())
                    })?;
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| ClientError::Tls(format!("client identity: {e}")))
            }
            None => Ok(builder.with_no_client_auth()),
        }
    }
}

/// Server cert verifier: full WebPKI chain validation against the
/// keystone CA roots, PLUS a sha256 pin on the leaf's
/// SubjectPublicKeyInfo. The pin is checked after chain validation so
/// a wrong-key cert still reports the ordinary chain error when it
/// has one — the pin only ever *adds* a rejection.
#[derive(Debug)]
struct SpkiPinVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pin: [u8; 32],
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let ee = webpki::EndEntityCert::try_from(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let spki_hash: [u8; 32] = Sha256::digest(ee.subject_public_key_info()).into();
        if spki_hash != self.pin {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

#[derive(Serialize)]
struct ExchangeRequest<'a> {
    account: &'a str,
    secret: &'a str,
    product: &'a str,
    #[serde(with = "serde_big_array::BigArray")]
    hwid: [u8; 32],
    #[serde(with = "serde_big_array::BigArray")]
    challenge: [u8; 32],
}

/// The signed payload inside an exchange envelope — the only place the
/// session key ever appears on the wire. Mirrors the server's
/// `ExchangeBody`; `revoked_key_ids` defaults so a server that predates
/// key revocation still parses.
#[derive(Deserialize)]
struct ExchangeBody {
    session_id: Uuid,
    #[serde(with = "serde_big_array::BigArray")]
    session_key: [u8; 32],
    lease: Lease,
    server_time: DateTime<Utc>,
    #[serde(default)]
    revoked_key_ids: Vec<u8>,
}

/// Every session-bound request carries `issued_at` — the client's
/// drift-adjusted clock — under the MAC. The server rejects anything
/// outside its skew window, which is what lets it forget the nonce
/// once the window closes instead of remembering it for the grant.
#[derive(Serialize)]
struct AttestRequest<'a> {
    session_id: Uuid,
    #[serde(with = "serde_big_array::BigArray")]
    challenge: [u8; 32],
    issued_at: DateTime<Utc>,
    process_id: &'a str,
    /// Server reads `Option<[u8; 32]>` — a bare array deserializes as
    /// `Some`, and we never send a MAC-less attest.
    #[serde(with = "serde_big_array::BigArray")]
    mac: [u8; 32],
}

#[derive(Serialize)]
struct HeartbeatRequest {
    session_id: Uuid,
    #[serde(with = "serde_big_array::BigArray")]
    nonce: [u8; 32],
    issued_at: DateTime<Utc>,
    #[serde(with = "serde_big_array::BigArray")]
    mac: [u8; 32],
}

#[derive(Serialize)]
struct RevokeRequest<'a> {
    session_id: Uuid,
    admin_token: &'a str,
}

#[derive(Serialize)]
struct PayloadRequest<'a> {
    session_id: Uuid,
    product: &'a str,
    version: &'a str,
    #[serde(with = "serde_big_array::BigArray")]
    nonce: [u8; 32],
    issued_at: DateTime<Utc>,
    /// Server reads `Option<[u8; 32]>` — a bare array deserializes as
    /// `Some`, and we never send a MAC-less payload request.
    #[serde(with = "serde_big_array::BigArray")]
    mac: [u8; 32],
}

/// Body of a payload.fetch envelope: the signed manifest and the
/// artifact key wrapped under session-derived material.
#[derive(Deserialize)]
struct PayloadBody {
    manifest: SignedManifest,
    payload_key_wrap: KeyWrap,
}

/// Body of attest/heartbeat envelopes: the renewed lease plus the
/// server's clock for drift checks. Mirrors the server's `LeaseBody`;
/// `revoked_key_ids` defaults so a server that predates key revocation
/// still parses.
#[derive(Deserialize)]
struct LeaseBody {
    lease: Lease,
    server_time: DateTime<Utc>,
    #[serde(default)]
    revoked_key_ids: Vec<u8>,
}

/// What a non-2xx response told us: the HTTP status, the
/// human-readable `error` message, and the machine-readable `code`
/// that decides whether the rejection is a verdict or transient.
struct Rejection {
    status: u16,
    code: Option<String>,
    message: String,
}

impl KeystoneClient {
    /// The primary constructor — pinning is not optional.
    ///
    /// `base_url` e.g. `https://key.example.com`. `issuers` is the set
    /// of issuer ed25519 verifying keys this client will ever accept,
    /// keyed by key id. Every consumer — loader and application alike
    /// — MUST bake its own `TrustedIssuers` into its build: the set is
    /// never learned from a handoff, a config file, or the network,
    /// because a party that can supply the trust root can forge every
    /// grant behind it. The only runtime mutation is shrinkage —
    /// [`Self::revoke_issuer_key`], or a revocation the server
    /// announces inside a signed body.
    ///
    /// `ca_cert_pem` is the keystone CA certificate in PEM — the ONLY
    /// trust root this client accepts; the public WebPKI root set is
    /// not consulted. `server_spki_sha256` pins the sha256 of the
    /// server certificate's SubjectPublicKeyInfo: chain validation
    /// still runs (expiry, SAN, CA signature), and the leaf's public
    /// key must additionally match the pin. The pin survives server
    /// cert rotation as long as the keypair is reused; rotating the
    /// server key means repinning clients — that is the point.
    ///
    /// `identity` — when `Some`, the client presents this certificate
    /// chain + key for mTLS. The server requires it whenever
    /// KEYSTONE_CA_CERT is configured.
    ///
    /// Requires https: credentials and session material cross this
    /// transport, and plaintext HTTP hands them to anyone on the path.
    /// For dev/test against a local server use [`Self::new_insecure`].
    pub fn new(
        base_url: impl Into<String>,
        issuers: TrustedIssuers,
        ca_cert_pem: impl AsRef<[u8]>,
        server_spki_sha256: [u8; 32],
        identity: Option<ClientIdentity>,
    ) -> Result<Self, ClientError> {
        let tls = PinnedTls {
            ca_cert_pem: ca_cert_pem.as_ref().to_vec(),
            server_spki_sha256,
            identity,
        };
        Self::build(base_url.into(), issuers, Some(tls), false)
    }

    /// WARNING: trusts the public WebPKI root set — any CA-issued cert
    /// for the hostname is accepted, so a compromised or coerced CA
    /// can intercept the transport. Envelope signatures still pin the
    /// issuer set, but the TLS layer gets no keystone-specific
    /// protection. Exists for deployments where the keystone CA is
    /// genuinely unavailable; prefer [`Self::new`].
    ///
    /// Requires https, same as [`Self::new`].
    pub fn new_unpinned_webpki(
        base_url: impl Into<String>,
        issuers: TrustedIssuers,
    ) -> Result<Self, ClientError> {
        Self::build(base_url.into(), issuers, None, false)
    }

    /// Dev/test constructor: permits `http://` base URLs. Never ship
    /// this — plaintext transport exposes credentials, the session
    /// key, and every MAC to anyone on the path.
    pub fn new_insecure(
        base_url: impl Into<String>,
        issuers: TrustedIssuers,
    ) -> Result<Self, ClientError> {
        Self::build(base_url.into(), issuers, None, true)
    }

    fn build(
        base_url: String,
        issuers: TrustedIssuers,
        tls: Option<PinnedTls>,
        allow_http: bool,
    ) -> Result<Self, ClientError> {
        let base_url = base_url.trim_end_matches('/').to_string();
        if !allow_http && !base_url.starts_with("https://") {
            return Err(ClientError::InsecureBaseUrl(base_url));
        }
        let mut builder = reqwest::Client::builder().timeout(REQUEST_TIMEOUT);
        if let Some(tls) = tls {
            builder = builder.use_preconfigured_tls(tls.client_config()?);
        }
        let http = builder.build().map_err(ClientError::Transport)?;
        Ok(Self {
            http,
            base_url,
            issuers: Arc::new(RwLock::new(issuers)),
        })
    }

    /// Stop trusting issuer key `key_id` — immediately, for this client
    /// and every clone sharing its set. Envelopes and manifests signed
    /// by it fail verification from the next call on (README: revoke
    /// the key AND invalidate affected sessions; the server handles
    /// the sessions). Revocation is permanent for the process: there
    /// is deliberately no way to re-trust a key at runtime.
    pub fn revoke_issuer_key(&self, key_id: u8) {
        self.issuers_mut().revoke(key_id);
    }

    /// Key ids currently accepted for verification — the baked set
    /// minus every revocation applied so far.
    pub fn trusted_key_ids(&self) -> Vec<u8> {
        let issuers = self.issuers();
        issuers
            .key_ids()
            .into_iter()
            .filter(|&key_id| !issuers.is_revoked(key_id))
            .collect()
    }

    /// Whether `key_id` has been revoked on this client.
    pub fn is_issuer_revoked(&self, key_id: u8) -> bool {
        self.issuers().is_revoked(key_id)
    }

    /// Apply revocations a signed body announced. Only ever called
    /// after the carrying envelope verified — an unverified body must
    /// not be able to shrink the set (a forged "revoke everything"
    /// would be a denial of service, not a compromise, but it is still
    /// an unauthenticated instruction).
    fn apply_revocations(&self, key_ids: &[u8]) {
        if key_ids.is_empty() {
            return;
        }
        let mut issuers = self.issuers_mut();
        for &key_id in key_ids {
            issuers.revoke(key_id);
        }
    }

    /// Read the trusted set. A poisoned lock is recovered rather than
    /// propagated: the set is only ever shrunk, so a panic mid-revoke
    /// leaves it at worst more restrictive, never less.
    fn issuers(&self) -> RwLockReadGuard<'_, TrustedIssuers> {
        self.issuers.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn issuers_mut(&self) -> RwLockWriteGuard<'_, TrustedIssuers> {
        self.issuers.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// POST a JSON body, returning the raw response so callers can
    /// classify the status themselves (heartbeat needs 403/410/other
    /// to drive the state machine differently).
    async fn post<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response, ClientError> {
        self.http
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .await
            .map_err(ClientError::Transport)
    }

    /// Parse a non-2xx body into a `Rejection`, pulling `{"error",
    /// "code"}` when the body cooperates.
    async fn parse_rejection(resp: reqwest::Response) -> Rejection {
        let status = resp.status().as_u16();
        match resp.json::<Value>().await {
            Ok(v) => Rejection {
                status,
                code: v.get("code").and_then(Value::as_str).map(str::to_owned),
                message: v
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| v.to_string()),
            },
            Err(_) => Rejection {
                status,
                code: None,
                message: "unreadable error body".to_string(),
            },
        }
    }

    /// Turn a non-2xx response into `ServerRejected` — for callers
    /// with no session to map the rejection onto (exchange, revoke).
    async fn rejection(resp: reqwest::Response) -> ClientError {
        let r = Self::parse_rejection(resp).await;
        ClientError::ServerRejected {
            status: r.status,
            message: r.message,
        }
    }

    /// Require a 2xx or convert the response into `ServerRejected`.
    async fn checked(resp: reqwest::Response) -> Result<reqwest::Response, ClientError> {
        if resp.status().is_success() {
            Ok(resp)
        } else {
            Err(Self::rejection(resp).await)
        }
    }

    /// Verify an envelope against the trusted issuer set and the
    /// bindings only this requester knows: the challenge we sent, the
    /// session we're in, and the audience/operation this response must
    /// be for. The envelope names its key id; an unknown or revoked id
    /// fails before the signature is even checked.
    ///
    /// `now` is the caller's best clock — session-bound callers pass
    /// `session.now()` so a skewed local clock can't misjudge
    /// freshness; exchange passes `Utc::now()` because no drift has
    /// been observed yet.
    fn verify_envelope(
        &self,
        env: &Envelope,
        challenge: &[u8; 32],
        session_id: &Uuid,
        audience: &str,
        operation: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ClientError> {
        let issuers = self.issuers();
        env.verify(
            &issuers,
            &Expectation {
                challenge,
                session_id,
                audience,
                operation,
                now,
            },
        )?;
        Ok(())
    }

    /// Verify a signed manifest against the trusted issuer set. Sync
    /// on purpose: the read guard must never be held across an await.
    fn verify_manifest<'m>(
        &self,
        signed: &'m SignedManifest,
        now: DateTime<Utc>,
    ) -> Result<&'m Manifest, ClientError> {
        let issuers = self.issuers();
        Ok(signed.verify(&issuers, now)?)
    }

    /// Gate for session-bound requests. Dead is final — surface the
    /// recorded reason without touching the wire, and never let a
    /// request attempt resurrect it. A Grace session past its deadline
    /// is the client's own call: the server may be unreachable and
    /// never gets a vote. Both checks run on drift-adjusted time.
    fn ensure_live(session: &mut ClientSession) -> Result<(), ClientError> {
        let now = session.now();
        match session.state() {
            SessionState::Dead { .. } => session.authorize(),
            SessionState::Grace { deadline, .. } if now > *deadline => {
                session.kill(DeadReason::GraceExhausted);
                Err(ClientError::GraceExhausted)
            }
            _ => Ok(()),
        }
    }

    /// Sessions opened from a handoff owe the server their own
    /// attestation before any session-bound call — README step 6
    /// is not skippable.
    fn ensure_attested(session: &ClientSession) -> Result<(), ClientError> {
        if session.is_pending_attest() {
            Err(ClientError::NotAuthenticated)
        } else {
            Ok(())
        }
    }

    /// Map a rejection onto the session. The `code` field decides
    /// first: `artifact_not_found`, `session_not_active`, and
    /// `rate_limited` are transient — a missing artifact or a session
    /// caught mid-transition must not murder the session. Without a
    /// transient code, 401/403/404/410 are verdicts — the server
    /// looked at the session and said no, so it dies now with no
    /// grace. Everything else (409, 5xx) is treated like a lost
    /// response: bounded grace, deadline fixed at first failure.
    fn apply_rejection(session: &mut ClientSession, status: u16, code: Option<&str>) {
        if let Some(
            CODE_ARTIFACT_NOT_FOUND
            | CODE_SESSION_NOT_ACTIVE
            | CODE_RATE_LIMITED
            | CODE_STALE_REQUEST,
        ) = code
        {
            session.on_transient_failure(session.now());
            return;
        }
        match status {
            // Bad MAC or unknown session — the key can never produce a
            // valid proof for a session the server doesn't hold, so
            // retrying is hopeless.
            401 | 404 => session.kill(DeadReason::Rejected),
            // "Denied" is a decision, not a failure.
            403 => session.kill(DeadReason::Revoked),
            // Expired or GraceExhausted server-side; our local state
            // tells which one the server must have seen.
            410 => {
                let reason = if matches!(session.state(), SessionState::Grace { .. }) {
                    DeadReason::GraceExhausted
                } else {
                    DeadReason::Expired
                };
                session.kill(reason);
            }
            _ => session.on_transient_failure(session.now()),
        }
    }

    /// Rejection handling for every session-bound route: parse the
    /// body, map code-then-status onto the session, and surface the
    /// `ServerRejected` to the caller.
    async fn reject(session: &mut ClientSession, resp: reqwest::Response) -> ClientError {
        let r = Self::parse_rejection(resp).await;
        Self::apply_rejection(session, r.status, r.code.as_deref());
        ClientError::ServerRejected {
            status: r.status,
            message: r.message,
        }
    }

    /// Shared epilogue for attest/heartbeat: verify the envelope, pull
    /// the lease out of its signed body, mark the nonce consumed.
    ///
    /// Every failure here — unparseable response, replayed nonce, bad
    /// signature, malformed body — is treated as a transient failure:
    /// active tampering must not be handled more leniently than
    /// silence, and the lease we already hold stays valid until its
    /// real expiry.
    async fn accept_lease_envelope(
        &self,
        session: &mut ClientSession,
        resp: reqwest::Response,
        challenge: &[u8; 32],
        audience: &str,
        operation: &str,
    ) -> Result<Lease, ClientError> {
        let accept = async {
            let env: Envelope = resp.json().await?;
            session.evict_expired_nonces(session.now());
            // Replay check on the envelope's OWN challenge field: a
            // stubbed or captured response replayed verbatim under a
            // fresh request nonce carries a nonce we've already spent.
            if session.is_nonce_consumed(&env.challenge) {
                return Err(ClientError::Core(KeystoneError::AlreadyConsumed));
            }
            self.verify_envelope(
                &env,
                challenge,
                &session.session_id(),
                audience,
                operation,
                session.now(),
            )?;
            let body: LeaseBody = serde_json::from_slice(&env.body).map_err(|e| {
                ClientError::Core(KeystoneError::Malformed(format!("{operation} body: {e}")))
            })?;
            Ok((body, env.expires_at))
        }
        .await;
        match accept {
            Ok((body, expires_at)) => {
                // Unreachable in practice — the is_nonce_consumed check
                // above already rejected a replay — but a consume error
                // must not install the lease.
                session.consume_nonce(*challenge, expires_at)?;
                session.observe_server_time(body.server_time);
                session.on_heartbeat_ok(body.lease.clone());
                // The body verified under a still-trusted key — its
                // revocation list is the server's word, applied now so
                // the very next envelope from a compromised key fails.
                self.apply_revocations(&body.revoked_key_ids);
                Ok(body.lease)
            }
            Err(e) => {
                session.on_transient_failure(session.now());
                Err(e)
            }
        }
    }

    /// Credential exchange: prove account+secret+entitlement, get back
    /// a signed envelope carrying the session id, session key, and
    /// first lease.
    ///
    /// The client mints the challenge — the verifier issues the nonce,
    /// the server echoes it inside the signed envelope. The envelope's
    /// challenge field must equal the nonce we sent — a captured
    /// exchange response replays with the wrong challenge and dies in
    /// `verify`. A response arriving after the challenge's own ttl is
    /// refused as expired.
    pub async fn exchange(
        &self,
        account: &str,
        secret: &str,
        product: &str,
        hwid: [u8; 32],
    ) -> Result<ClientSession, ClientError> {
        let challenge = Challenge::fresh(Duration::seconds(CHALLENGE_TTL_SECS));
        let resp = Self::checked(
            self.post(
                "/exchange",
                &ExchangeRequest {
                    account,
                    secret,
                    product,
                    hwid,
                    challenge: challenge.nonce,
                },
            )
            .await?,
        )
        .await?;
        if challenge.is_expired(Utc::now()) {
            return Err(ClientError::Core(KeystoneError::Expired));
        }
        let env: Envelope = resp.json().await?;
        // The session_id needed for verification lives inside the
        // signed body; reading it before verify is safe because
        // Expectation binds it — a forged body id fails the envelope's
        // own session_id check, which the signature covers.
        let body: ExchangeBody = serde_json::from_slice(&env.body).map_err(|e| {
            ClientError::Core(KeystoneError::Malformed(format!("exchange body: {e}")))
        })?;
        self.verify_envelope(
            &env,
            &challenge.nonce,
            &body.session_id,
            AUDIENCE_CLIENT,
            OP_EXCHANGE,
            // No session exists yet — no drift has been observed, so
            // raw local time is all we have.
            Utc::now(),
        )?;
        let mut session = ClientSession::new(body.session_id, body.session_key, body.lease);
        // The exchange envelope is accepted — its nonce is spent so a
        // replay of the same signed response is rejected on sight.
        session.observe_server_time(body.server_time);
        session.consume_nonce(challenge.nonce, env.expires_at)?;
        self.apply_revocations(&body.revoked_key_ids);
        Ok(session)
    }

    /// Application-side attestation (README step 6): the app never
    /// trusts "the client already checked" — it presents the session,
    /// proves key possession with a MAC over a challenge it minted
    /// itself (bound to the session and a drift-adjusted `issued_at`),
    /// and gets its own signed lease echoing that challenge.
    ///
    /// Takes `&mut` for the same reason heartbeat does: an explicit
    /// server rejection (401/403/404/410) kills the session — it must
    /// not keep authorizing on a lease the server has disowned.
    pub async fn attest(
        &self,
        session: &mut ClientSession,
        process_id: &str,
    ) -> Result<Lease, ClientError> {
        Self::ensure_live(session)?;

        let challenge = Challenge::fresh(Duration::seconds(CHALLENGE_TTL_SECS));
        let issued_at = session.now();
        let mac = mac_request(
            session.session_key()?,
            &RequestBinding {
                session_id: &session.session_id(),
                nonce: &challenge.nonce,
                issued_at,
                context: b"attest",
            },
        );
        let resp = match self
            .post(
                "/attest",
                &AttestRequest {
                    session_id: session.session_id(),
                    challenge: challenge.nonce,
                    issued_at,
                    process_id,
                    mac,
                },
            )
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                session.on_transient_failure(session.now());
                return Err(e);
            }
        };
        if !resp.status().is_success() {
            return Err(Self::reject(session, resp).await);
        }
        // The challenge's ttl is our own bound on the echo, measured
        // on the same raw local clock that minted it — drift never
        // enters. Stale is transient, same as any unverifiable
        // response.
        if challenge.is_expired(Utc::now()) {
            session.on_transient_failure(session.now());
            return Err(ClientError::Core(KeystoneError::Expired));
        }
        let lease = self
            .accept_lease_envelope(session, resp, &challenge.nonce, AUDIENCE_APP, OP_ATTEST)
            .await?;
        // The app proved session-key possession to the server — the
        // pending gate lifts and the attested lease is installed.
        session.clear_pending_attest();
        Ok(lease)
    }

    /// Renew the lease. Drives the session state machine:
    ///
    /// - success → `on_heartbeat_ok` (lease refreshed, grace cleared)
    /// - transport error / unrecognized status / unverifiable response
    ///   → `on_transient_failure` (grace deadline fixed on first
    ///   failure, never extended)
    /// - 401/403/404/410 → explicit rejection, `kill` — no grace for
    ///   "denied" or "gone"
    pub async fn heartbeat(&self, session: &mut ClientSession) -> Result<Lease, ClientError> {
        Self::ensure_live(session)?;
        Self::ensure_attested(session)?;

        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let issued_at = session.now();
        let mac = mac_request(
            session.session_key()?,
            &RequestBinding {
                session_id: &session.session_id(),
                nonce: &nonce,
                issued_at,
                context: b"heartbeat",
            },
        );

        let resp = match self
            .post(
                "/heartbeat",
                &HeartbeatRequest {
                    session_id: session.session_id(),
                    nonce,
                    issued_at,
                    mac,
                },
            )
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                // The server never saw this request — its view of the
                // session is unchanged, so grace is the honest posture.
                session.on_transient_failure(session.now());
                return Err(e);
            }
        };

        if !resp.status().is_success() {
            return Err(Self::reject(session, resp).await);
        }

        self.accept_lease_envelope(session, resp, &nonce, AUDIENCE_CLIENT, OP_HEARTBEAT)
            .await
    }

    /// Operator path: revoke a session server-side. Requires the admin
    /// token the server was configured with; without one the route is
    /// closed entirely (403).
    pub async fn revoke(&self, session_id: Uuid, admin_token: &str) -> Result<(), ClientError> {
        Self::checked(
            self.post(
                "/revoke",
                &RevokeRequest {
                    session_id,
                    admin_token,
                },
            )
            .await?,
        )
        .await?;
        Ok(())
    }

    /// Fetch the signed manifest and artifact key for a release.
    ///
    /// The request is MAC'd with the session key over a fresh nonce and
    /// drift-adjusted `issued_at`, bound to `product:version` — a
    /// captured manifest is useless without a live session, because
    /// both the MAC and the key-wrap salt need key material only the
    /// session holds. Returns the verified manifest plus the unwrapped
    /// artifact decryption key.
    ///
    /// Takes `&mut` like attest/heartbeat: an explicit server rejection
    /// kills the session, and the request nonce is consumed so a
    /// replayed envelope is rejected on sight.
    pub async fn fetch_manifest(
        &self,
        session: &mut ClientSession,
        product: &str,
        version: &str,
    ) -> Result<(SignedManifest, [u8; 32]), ClientError> {
        Self::ensure_live(session)?;
        Self::ensure_attested(session)?;

        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let issued_at = session.now();
        // The MAC context binds product+version via the length-prefixed
        // artifact context — must match routes.rs byte for byte.
        let context = [
            b"payload.fetch:".as_slice(),
            &artifact_context(product, version, MAC_CONTEXT_EPOCH),
        ]
        .concat();
        let mac = mac_request(
            session.session_key()?,
            &RequestBinding {
                session_id: &session.session_id(),
                nonce: &nonce,
                issued_at,
                context: &context,
            },
        );

        let resp = match self
            .post(
                "/payload",
                &PayloadRequest {
                    session_id: session.session_id(),
                    product,
                    version,
                    nonce,
                    issued_at,
                    mac,
                },
            )
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                session.on_transient_failure(session.now());
                return Err(e);
            }
        };
        if !resp.status().is_success() {
            return Err(Self::reject(session, resp).await);
        }

        // Same posture as accept_lease_envelope: anything that fails
        // verification is transient — active tampering gets no
        // harsher treatment than silence, and the lease we hold stays
        // valid until its real expiry.
        let accept = async {
            let env: Envelope = resp.json().await?;
            session.evict_expired_nonces(session.now());
            // Same replay posture as accept_lease_envelope: check the
            // envelope's own challenge — a replayed manifest envelope
            // carries a spent nonce no matter what we sent.
            if session.is_nonce_consumed(&env.challenge) {
                return Err(ClientError::Core(KeystoneError::AlreadyConsumed));
            }
            if session.is_nonce_consumed(&nonce) {
                return Err(ClientError::Core(KeystoneError::AlreadyConsumed));
            }
            self.verify_envelope(
                &env,
                &nonce,
                &session.session_id(),
                AUDIENCE_APP,
                OP_PAYLOAD_FETCH,
                session.now(),
            )?;
            let body: PayloadBody = serde_json::from_slice(&env.body).map_err(|e| {
                ClientError::Core(KeystoneError::Malformed(format!("payload body: {e}")))
            })?;
            // The manifest's own signature is verified here, before it
            // ever reaches the caller — nothing unverified propagates.
            let manifest = self.verify_manifest(&body.manifest, session.now())?;
            // The signed manifest must attest what we asked for — a
            // manifest for another artifact is a mismatch, not a grant.
            if manifest.product != product || manifest.version != version {
                return Err(ClientError::Core(KeystoneError::Malformed(
                    "manifest product/version mismatch".into(),
                )));
            }
            // Unwrap the artifact key under session-derived material —
            // only this session+nonce can open it.
            let artifact_key =
                unwrap_artifact_key(session.session_key()?, &nonce, &body.payload_key_wrap)?;
            Ok((body.manifest, artifact_key, env.expires_at))
        }
        .await;
        match accept {
            Ok((manifest, artifact_key, expires_at)) => {
                session.consume_nonce(nonce, expires_at)?;
                Ok((manifest, artifact_key))
            }
            Err(e) => {
                session.on_transient_failure(session.now());
                Err(e)
            }
        }
    }

    /// Download, decrypt, and verify the payload blob.
    ///
    /// Fetches the manifest first — the blob is meaningless without the
    /// hash the signature attests — then GETs the sealed artifact with
    /// a MAC in the Authorization header (session id, nonce, and
    /// drift-adjusted `issued_at` in millis, all under the tag),
    /// decrypts it with the unwrapped artifact key, and refuses to
    /// return bytes that don't match the manifest. Callers get verified
    /// plaintext or an error, never unverified bytes.
    pub async fn download_payload(
        &self,
        session: &mut ClientSession,
        product: &str,
        version: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let (signed, artifact_key) = self.fetch_manifest(session, product, version).await?;

        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let issued_at = session.now();
        let context = [
            b"payload.download:".as_slice(),
            &artifact_context(product, version, MAC_CONTEXT_EPOCH),
        ]
        .concat();
        let mac = mac_request(
            session.session_key()?,
            &RequestBinding {
                session_id: &session.session_id(),
                nonce: &nonce,
                issued_at,
                context: &context,
            },
        );
        let auth = format!(
            "Keystone {}:{}:{}:{}",
            session.session_id(),
            hex::encode(nonce),
            issued_at.timestamp_millis(),
            hex::encode(mac),
        );

        let resp = match self
            .http
            .get(format!("{}/payload/{product}/{version}", self.base_url))
            .header(reqwest::header::AUTHORIZATION, auth)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                session.on_transient_failure(session.now());
                return Err(ClientError::Transport(e));
            }
        };
        if !resp.status().is_success() {
            return Err(Self::reject(session, resp).await);
        }

        // Bounded read: a hostile or broken server must not grow this
        // buffer past the artifact cap.
        let mut sealed = Vec::new();
        let mut resp = resp;
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    if sealed.len() as u64 + chunk.len() as u64 > MAX_ARTIFACT_BYTES {
                        session.on_transient_failure(session.now());
                        return Err(ClientError::Core(KeystoneError::Malformed(
                            "payload exceeds artifact size cap".into(),
                        )));
                    }
                    sealed.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    session.on_transient_failure(session.now());
                    return Err(ClientError::Transport(e));
                }
            }
        }

        // Decrypt first, hash second: a tampered blob dies on the
        // Poly1305 tag; an intact-but-wrong blob dies on the manifest's
        // attested sha256. Either way unverified bytes never return.
        let plaintext = match decrypt_artifact(&artifact_key, &sealed) {
            Ok(p) => p,
            Err(e) => {
                session.on_transient_failure(session.now());
                return Err(ClientError::Core(e));
            }
        };
        signed.manifest.verify_payload(&plaintext)?;
        Ok(plaintext)
    }
}
