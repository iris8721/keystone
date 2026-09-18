//! `KeystoneClient` — the SDK surface loaders and payloads link against.
//!
//! The client is never the authority (DESIGN.md): it collects
//! credentials, proves session-key possession, and verifies that every
//! grant it accepts was signed by the one pinned issuer key. Anything
//! that fails verification is treated as if it never arrived.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::VerifyingKey;
use keystone_core::{
    artifact_context, decrypt_artifact, mac_heartbeat, mac_response, unwrap_artifact_key,
    Challenge, DeadReason, Envelope, Expectation, KeystoneError, KeyWrap, Lease, SessionState,
    SignedManifest, MAX_ARTIFACT_BYTES,
};
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, ServerName, UnixTime,
};
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

/// Server error codes that mean "transient, not a verdict" — the
/// session survives these. Must match routes.rs exactly.
const CODE_BAD_CHALLENGE: &str = "bad_challenge";
const CODE_ARTIFACT_NOT_FOUND: &str = "artifact_not_found";
const CODE_SESSION_NOT_ACTIVE: &str = "session_not_active";
const CODE_RATE_LIMITED: &str = "rate_limited";

/// Hard cap on any single request. Bounded well under any sane
/// lease_ttl so a blackholed connection surfaces as a transient
/// failure — and the grace clock starts — instead of hanging the
/// caller past the point where the lease was already dead.
const REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(10);

/// Client for the keystone-server authorization surface.
///
/// `pinned_key` is the whole point: the client trusts exactly one
/// issuer. No CA, no key rollover, no "trusted" third party — an
/// envelope that doesn't verify against this key is garbage.
#[derive(Clone)]
pub struct KeystoneClient {
    http: reqwest::Client,
    base_url: String,
    pinned_key: VerifyingKey,
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
        let webpki = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
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
                let key: PrivateKeyDer<'static> =
                    rustls_pemfile::private_key(&mut &id.key_pem[..])
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


/// Wire shape of POST /challenge's response.
#[derive(Deserialize)]
struct ChallengeResponse {
    #[serde(with = "serde_big_array::BigArray")]
    nonce: [u8; 32],
    issued_at: DateTime<Utc>,
    ttl_secs: i64,
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
/// session key ever appears on the wire.
#[derive(Deserialize)]
struct ExchangeBody {
    session_id: Uuid,
    #[serde(with = "serde_big_array::BigArray")]
    session_key: [u8; 32],
    lease: Lease,
    server_time: DateTime<Utc>,
}

#[derive(Serialize)]
struct AttestRequest<'a> {
    session_id: Uuid,
    #[serde(with = "serde_big_array::BigArray")]
    challenge: [u8; 32],
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
/// server's clock for drift checks.
#[derive(Deserialize)]
struct LeaseBody {
    lease: Lease,
    server_time: DateTime<Utc>,
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
    /// `base_url` e.g. `https://key.example.com`. `pinned_key` is the
    /// issuer's ed25519 verifying key, baked into the build — the only
    /// key this client will ever accept.
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
        pinned_key: VerifyingKey,
        ca_cert_pem: impl AsRef<[u8]>,
        server_spki_sha256: [u8; 32],
        identity: Option<ClientIdentity>,
    ) -> Result<Self, ClientError> {
        let tls = PinnedTls {
            ca_cert_pem: ca_cert_pem.as_ref().to_vec(),
            server_spki_sha256,
            identity,
        };
        Self::build(base_url.into(), pinned_key, Some(tls), false)
    }

    /// WARNING: trusts the public WebPKI root set — any CA-issued cert
    /// for the hostname is accepted, so a compromised or coerced CA
    /// can intercept the transport. Envelope signatures still pin the
    /// issuer key, but the TLS layer gets no keystone-specific
    /// protection. Exists for deployments where the keystone CA is
    /// genuinely unavailable; prefer [`Self::new`].
    ///
    /// Requires https, same as [`Self::new`].
    pub fn new_unpinned_webpki(
        base_url: impl Into<String>,
        pinned_key: VerifyingKey,
    ) -> Result<Self, ClientError> {
        Self::build(base_url.into(), pinned_key, None, false)
    }

    /// Dev/test constructor: permits `http://` base URLs. Never ship
    /// this — plaintext transport exposes credentials, the session
    /// key, and every MAC to anyone on the path.
    pub fn new_insecure(
        base_url: impl Into<String>,
        pinned_key: VerifyingKey,
    ) -> Result<Self, ClientError> {
        Self::build(base_url.into(), pinned_key, None, true)
    }

    fn build(
        base_url: String,
        pinned_key: VerifyingKey,
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
            pinned_key,
        })
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
                code: v
                    .get("code")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
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

    /// Verify an envelope against the pinned key and the bindings only
    /// this requester knows: the challenge we sent, the session we're
    /// in, and the audience/operation this response must be for.
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
        env.verify(
            &self.pinned_key,
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
    /// attestation before any session-bound call — DESIGN.md step 6
    /// is not skippable.
    fn ensure_attested(session: &ClientSession) -> Result<(), ClientError> {
        if session.is_pending_attest() {
            Err(ClientError::NotAuthenticated)
        } else {
            Ok(())
        }
    }

    /// Map a rejection onto the session. The `code` field decides
    /// first: `bad_challenge`, `artifact_not_found`,
    /// `session_not_active`, and `rate_limited` are transient — a
    /// delayed attest or a missing artifact must not murder the
    /// session. Without a transient code, 401/403/404/410 are verdicts
    /// — the server looked at the session and said no, so it dies now
    /// with no grace. Everything else (409, 5xx) is treated like a
    /// lost response: bounded grace, deadline fixed at first failure.
    fn apply_rejection(session: &mut ClientSession, status: u16, code: Option<&str>) {
        if let Some(
            CODE_BAD_CHALLENGE
            | CODE_ARTIFACT_NOT_FOUND
            | CODE_SESSION_NOT_ACTIVE
            | CODE_RATE_LIMITED,
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
            Ok((body.lease, env.expires_at, body.server_time))
        }
        .await;
        match accept {
            Ok((lease, expires_at, server_time)) => {
                // Unreachable in practice — the is_nonce_consumed check
                // above already rejected a replay — but a consume error
                // must not install the lease.
                session.consume_nonce(*challenge, expires_at)?;
                session.observe_server_time(server_time);
                session.on_heartbeat_ok(lease.clone());
                Ok(lease)
            }
            Err(e) => {
                session.on_transient_failure(session.now());
                Err(e)
            }
        }
    }

    /// Mint a fresh server challenge. The nonce must be echoed into
    /// the next request and comes back inside the signed envelope —
    /// that round-trip is the anti-replay binding.
    pub async fn challenge(&self) -> Result<Challenge, ClientError> {
        let resp = Self::checked(self.post("/challenge", &Value::Object(Default::default())).await?)
            .await?;
        let wire: ChallengeResponse = resp.json().await?;
        Ok(Challenge::from_parts(
            wire.nonce,
            wire.issued_at,
            Duration::seconds(wire.ttl_secs),
        ))
    }

    /// Credential exchange: prove account+secret+entitlement, get back
    /// a signed envelope carrying the session id, session key, and
    /// first lease.
    ///
    /// The envelope's challenge field must equal the nonce we sent —
    /// a captured exchange response replays with the wrong challenge
    /// and dies in `verify`.
    pub async fn exchange(
        &self,
        account: &str,
        secret: &str,
        product: &str,
        hwid: [u8; 32],
    ) -> Result<ClientSession, ClientError> {
        let challenge = self.challenge().await?;
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
        let mut session = ClientSession::new(
            body.session_id,
            body.session_key,
            body.lease,
            self.pinned_key.to_bytes(),
        );
        // The exchange envelope is accepted — its nonce is spent so a
        // replay of the same signed response is rejected on sight.
        session.observe_server_time(body.server_time);
        session.consume_nonce(challenge.nonce, env.expires_at)?;
        Ok(session)
    }

    /// Application-side attestation (DESIGN.md step 6): the app never
    /// trusts "the client already checked" — it presents the session,
    /// proves key possession with a MAC over a fresh server challenge,
    /// and gets its own signed lease.
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

        // Attest burns a server-issued challenge; if we can't get one
        // the server is unreachable — same posture as a lost response.
        let challenge = match self.challenge().await {
            Ok(c) => c,
            Err(e) => {
                session.on_transient_failure(session.now());
                return Err(e);
            }
        };
        let mac = mac_response(session.session_key()?, &challenge.nonce, b"attest");
        let resp = match self
            .post(
                "/attest",
                &AttestRequest {
                    session_id: session.session_id(),
                    challenge: challenge.nonce,
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
        let mac = mac_heartbeat(session.session_key()?, &session.session_id(), &nonce);

        let resp = match self
            .post(
                "/heartbeat",
                &HeartbeatRequest {
                    session_id: session.session_id(),
                    nonce,
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
    pub async fn revoke(
        &self,
        session_id: Uuid,
        admin_token: &str,
    ) -> Result<(), ClientError> {
        Self::checked(
            self.post("/revoke", &RevokeRequest { session_id, admin_token })
                .await?,
        )
        .await?;
        Ok(())
    }

    /// Fetch the signed manifest and artifact key for a release.
    ///
    /// The request is MAC'd with the session key over a fresh nonce and
    /// bound to `product:version` — a captured manifest is useless
    /// without a live session, because both the MAC and the key-wrap
    /// salt need key material only the session holds. Returns the
    /// verified manifest plus the unwrapped artifact decryption key.
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
        // The MAC body binds product+version via the length-prefixed
        // artifact context — must match routes.rs byte for byte.
        let mac_body = [b"payload.fetch:".as_slice(), &artifact_context(product, version)].concat();
        let mac = mac_response(session.session_key()?, &nonce, &mac_body);

        let resp = match self
            .post(
                "/payload",
                &PayloadRequest {
                    session_id: session.session_id(),
                    product,
                    version,
                    nonce,
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
            let manifest = body.manifest.verify(&self.pinned_key, session.now())?;
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
    /// a MAC in the Authorization header, decrypts it with the
    /// unwrapped artifact key, and refuses to return bytes that don't
    /// match the manifest. Callers get verified plaintext or an error,
    /// never unverified bytes.
    pub async fn download_payload(
        &self,
        session: &mut ClientSession,
        product: &str,
        version: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let (signed, artifact_key) = self.fetch_manifest(session, product, version).await?;

        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let mac_body =
            [b"payload.download:".as_slice(), &artifact_context(product, version)].concat();
        let mac = mac_response(session.session_key()?, &nonce, &mac_body);
        let auth = format!(
            "Keystone {}:{}:{}",
            session.session_id(),
            hex::encode(nonce),
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
