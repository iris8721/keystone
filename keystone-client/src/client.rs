//! [`KeystoneClient`]: exchange, handoff, attest, heartbeat, and payload
//! requests against a keystone server. Every response is verified against
//! the issuer set baked into the build before anything it carries is used.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration as StdDuration;

use chrono::{Duration, Utc};
use keystone_core::wire::{
    AUDIENCE_APP, AUDIENCE_CLIENT, AttestBody, AttestRequest, DownloadAuthorization, ExchangeBody,
    ExchangeRequest, HandoffBody, HandoffRequest, HeartbeatRequest, LeaseBody, MAX_HANDOFF_TTL,
    OP_ATTEST, OP_EXCHANGE, OP_HANDOFF, OP_HEARTBEAT, OP_PAYLOAD_FETCH, PayloadBody,
    PayloadRequest, Verdict, mac_context, paths, validate_release,
};
use keystone_core::{
    BootstrapExpectation, Challenge, DeadReason, Envelope, Expectation, HandoffPayload,
    HandoffToken, KeystoneError, MAX_ARTIFACT_BYTES, RequestBinding, SignedManifest,
    TrustedIssuers, decrypt_artifact, handoff_wrap_key, mac_request, unwrap_secret,
};
use zeroize::Zeroizing;

use crate::error::{ClientError, session_verdict};
use crate::session::{ClientSession, PendingSession, SessionClock};
use crate::transport::{
    ClientIdentity, Transport, TransportOptions, accept_json, parse_json, read_capped, rejection,
};

/// Configures a [`KeystoneClient`]. Without a CA the public WebPKI roots
/// are trusted; with one or more SPKI pins the server's leaf key must match
/// a pin, which replaces hostname verification (and chain validation too
/// when no CA is set).
#[derive(Debug)]
pub struct ClientBuilder {
    options: TransportOptions,
    issuers: TrustedIssuers,
}

impl ClientBuilder {
    /// Trust only this PEM CA (one or more certificates) for the server chain.
    pub fn server_ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.options.server_ca_pem(pem.into());
        self
    }

    /// Accept a server whose leaf SubjectPublicKeyInfo hashes (sha256) to
    /// `spki_sha256`. Repeatable, so a key rotation can be pinned ahead.
    pub fn pin_spki(mut self, spki_sha256: [u8; 32]) -> Self {
        self.options.pin_spki(spki_sha256);
        self
    }

    /// Present this certificate and key for mTLS.
    pub fn identity(mut self, identity: ClientIdentity) -> Self {
        self.options.identity(identity);
        self
    }

    /// Permit a plaintext `http://` base URL. Development only: credentials
    /// and session material cross the wire in the clear.
    pub fn allow_insecure_http(mut self) -> Self {
        self.options.allow_insecure_http();
        self
    }

    /// Cap on each JSON request, connect through body; default 10 s.
    pub fn timeout(mut self, timeout: StdDuration) -> Self {
        self.options.timeout(timeout);
        self
    }

    /// Cap on the artifact download, connect through last byte; default
    /// 10 min. Every response body also fails after 30 s without new bytes.
    pub fn download_timeout(mut self, timeout: StdDuration) -> Self {
        self.options.download_timeout(timeout);
        self
    }

    /// Build the client. Fails with `InvalidConfig` on a non-https URL
    /// (unless insecure http is allowed), TLS options on an http URL, or
    /// unparseable PEM.
    pub fn build(self) -> Result<KeystoneClient, ClientError> {
        Ok(KeystoneClient {
            transport: self.options.build()?,
            issuers: Arc::new(RwLock::new(self.issuers)),
        })
    }
}

/// A verified release: the signed manifest and the decrypted payload whose
/// sha256 matches it.
#[derive(Clone)]
pub struct Payload {
    /// The manifest the payload was verified against.
    pub manifest: SignedManifest,
    /// Decrypted payload bytes.
    pub bytes: Vec<u8>,
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Payload")
            .field("manifest", &self.manifest)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

/// Client for the keystone public API. Clones share the HTTP pool and the
/// trusted issuer set, so a key revocation learned by one applies to all.
#[derive(Clone)]
pub struct KeystoneClient {
    transport: Transport,
    issuers: Arc<RwLock<TrustedIssuers>>,
}

impl fmt::Debug for KeystoneClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeystoneClient")
            .field("transport", &self.transport)
            .field("issuers", &*self.issuers())
            .finish()
    }
}

impl KeystoneClient {
    /// Start configuring a client for `base_url` (e.g.
    /// `https://key.example.com`). `issuers` must be baked into the build;
    /// it is never learned from the network and only ever shrinks.
    pub fn builder(base_url: impl Into<String>, issuers: TrustedIssuers) -> ClientBuilder {
        ClientBuilder {
            options: TransportOptions::new(base_url.into()),
            issuers,
        }
    }

    /// Stop trusting issuer key `key_id` for this client and its clones.
    /// Permanent for the process.
    pub fn revoke_issuer_key(&self, key_id: u8) {
        self.issuers_mut().revoke(key_id);
    }

    /// Key ids still accepted for verification.
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

    /// Exchange account credentials for a loader session. The exchange
    /// envelope sets the session clock. Fails with `Core` when a field
    /// exceeds its wire cap, `ServerRejected` on refusal, `InvalidResponse`
    /// when the envelope does not verify.
    pub async fn exchange(
        &self,
        account: &str,
        secret: &str,
        product: &str,
        hwid: [u8; 32],
    ) -> Result<ClientSession, ClientError> {
        let challenge = Challenge::new();
        let request = ExchangeRequest {
            account: account.to_owned(),
            secret: Zeroizing::new(secret.to_owned()),
            product: product.to_owned(),
            hwid,
            challenge: challenge.nonce,
        };
        request.validate()?;
        let env: Envelope =
            accept_json(self.transport.post(paths::EXCHANGE, &request).await?).await?;
        let body: ExchangeBody = parse_json(&env.body, "exchange body")?;
        // The body's session id is covered by the envelope signature.
        let drift = env
            .verify_bootstrap(
                &self.issuers(),
                &BootstrapExpectation {
                    challenge: &challenge,
                    session_id: &body.session_id,
                    audience: AUDIENCE_CLIENT,
                    operation: OP_EXCHANGE,
                },
            )
            .map_err(ClientError::InvalidResponse)?;
        let server_now = Utc::now()
            .checked_add_signed(drift)
            .ok_or_else(|| invalid("exchange clock"))?;
        let ExchangeBody {
            session_id,
            session_key,
            lease,
            features,
            revoked_key_ids,
            ..
        } = body;
        let session = ClientSession::new(
            session_id,
            product.to_owned(),
            session_key,
            lease,
            features,
            SessionClock::starting_at(server_now),
        );
        session.consume(challenge.nonce, env.expires_at)?;
        self.apply_revocations(&revoked_key_ids);
        Ok(session)
    }

    /// Mint a single-use handoff for a child process claiming `process_id`,
    /// valid for `ttl` (clamped to `MAX_HANDOFF_TTL` and the server's
    /// expiry). Deliver the token with [`crate::handoff::spawn_with_handoff`].
    /// A kill verdict ends `session`.
    pub async fn create_handoff(
        &self,
        session: &ClientSession,
        process_id: &str,
        ttl: Duration,
    ) -> Result<HandoffToken, ClientError> {
        session.authorize()?;
        let result = self.request_handoff(session, process_id, ttl).await;
        settle(session, result)
    }

    async fn request_handoff(
        &self,
        session: &ClientSession,
        process_id: &str,
        ttl: Duration,
    ) -> Result<HandoffToken, ClientError> {
        let challenge = Challenge::new();
        let ttl_millis = u64::try_from(ttl.min(MAX_HANDOFF_TTL).num_milliseconds()).unwrap_or(0);
        let issued_at = session.now();
        let context = mac_context::handoff(process_id, ttl_millis);
        let request = HandoffRequest {
            session_id: session.session_id(),
            nonce: challenge.nonce,
            issued_at,
            process_id: process_id.to_owned(),
            ttl_millis,
            mac: session.mac(&challenge.nonce, issued_at, &context)?,
        };
        request.validate()?;
        let env: Envelope =
            accept_json(self.transport.post(paths::HANDOFF, &request).await?).await?;
        self.verify(
            &env,
            &Expectation {
                challenge: &challenge,
                session_id: &session.session_id(),
                audience: AUDIENCE_CLIENT,
                operation: OP_HANDOFF,
                now: session.now(),
            },
        )?;
        let body: HandoffBody = parse_json(&env.body, "handoff body")?;
        let clock =
            SessionClock::from_response(body.server_time, challenge.minted, body.expires_at)?;
        session.consume(challenge.nonce, env.expires_at)?;
        session.set_clock(clock);
        self.apply_revocations(&body.revoked_key_ids);

        let token_ttl = request.ttl().min(body.expires_at - session.now());
        if token_ttl <= Duration::zero() {
            return Err(ClientError::InvalidResponse(KeystoneError::Expired));
        }
        let payload = HandoffPayload {
            parent_session_id: session.session_id(),
            handoff_id: body.handoff_id,
            handoff_secret: *body.handoff_secret,
            product: session.product().to_owned(),
            expires_at: body.expires_at,
            server_offset_millis: session.server_offset().num_milliseconds(),
        };
        Ok(HandoffToken::seal(&payload, process_id, token_ttl)?)
    }

    /// Redeem a handoff, as the identity it was opened with, for the child's
    /// own session, whose key arrives wrapped under the handoff secret. The
    /// handoff is spent whether or not this succeeds.
    pub async fn attest(&self, pending: PendingSession) -> Result<ClientSession, ClientError> {
        let handoff = pending.payload();
        let process_id = pending.process_id();
        let clock = pending.clock();
        let challenge = Challenge::new();
        let issued_at = clock.now();
        let mac = mac_request(
            &handoff.handoff_secret,
            &RequestBinding {
                session_id: &handoff.parent_session_id,
                nonce: &challenge.nonce,
                issued_at,
                context: &mac_context::attest(&handoff.handoff_id, process_id),
            },
        );
        let request = AttestRequest {
            parent_session_id: handoff.parent_session_id,
            handoff_id: handoff.handoff_id,
            challenge: challenge.nonce,
            issued_at,
            process_id: process_id.to_owned(),
            mac,
        };
        request.validate()?;
        let env: Envelope =
            accept_json(self.transport.post(paths::ATTEST, &request).await?).await?;
        let body: AttestBody = parse_json(&env.body, "attest body")?;
        // The child session id is covered by the envelope signature.
        self.verify(
            &env,
            &Expectation {
                challenge: &challenge,
                session_id: &body.session_id,
                audience: AUDIENCE_APP,
                operation: OP_ATTEST,
                now: clock.now(),
            },
        )?;
        let key = unwrap_secret(
            &handoff_wrap_key(&handoff.handoff_secret, &challenge.nonce),
            &body.session_key_wrap,
        )
        .map_err(ClientError::InvalidResponse)?;
        let clock =
            SessionClock::from_response(body.server_time, challenge.minted, body.lease.expires_at)?;
        let session = ClientSession::new(
            body.session_id,
            handoff.product.clone(),
            key,
            body.lease,
            body.features,
            clock,
        );
        session.consume(challenge.nonce, env.expires_at)?;
        self.apply_revocations(&body.revoked_key_ids);
        Ok(session)
    }

    /// Renew the lease. Success installs the new lease and features and
    /// clears grace; a transient failure starts grace; a kill verdict ends
    /// the session; every failure schedules a backed-off retry reported by
    /// [`ClientSession::next_heartbeat_due`].
    pub async fn heartbeat(&self, session: &ClientSession) -> Result<(), ClientError> {
        session.authorize()?;
        let result = self.renew(session).await;
        if let Err(e) = &result {
            session.heartbeat_failed(failure_verdict(e));
        }
        result
    }

    async fn renew(&self, session: &ClientSession) -> Result<(), ClientError> {
        let challenge = Challenge::new();
        let issued_at = session.now();
        let request = HeartbeatRequest {
            session_id: session.session_id(),
            nonce: challenge.nonce,
            issued_at,
            mac: session.mac(&challenge.nonce, issued_at, &mac_context::heartbeat())?,
        };
        request.validate()?;
        let env: Envelope =
            accept_json(self.transport.post(paths::HEARTBEAT, &request).await?).await?;
        self.verify(
            &env,
            &Expectation {
                challenge: &challenge,
                session_id: &session.session_id(),
                audience: AUDIENCE_CLIENT,
                operation: OP_HEARTBEAT,
                now: session.now(),
            },
        )?;
        let body: LeaseBody = parse_json(&env.body, "heartbeat body")?;
        let clock =
            SessionClock::from_response(body.server_time, challenge.minted, body.lease.expires_at)?;
        session.consume(challenge.nonce, env.expires_at)?;
        self.apply_revocations(&body.revoked_key_ids);
        session.install_lease(body.lease, body.features, clock);
        session.authorize()
    }

    /// Keep the session alive until it dies: sleep until the next heartbeat
    /// is due on the session clock, renew, and on failure retry with
    /// jittered exponential backoff that never outlasts the grace deadline.
    /// Once renewals stop extending the lease it sleeps until expiry. Other
    /// clones of `session` stay usable meanwhile. Returns why it ended.
    pub async fn run_keepalive(&self, session: &ClientSession) -> DeadReason {
        loop {
            let Some(due) = session.next_heartbeat_due() else {
                let reason = session.dead_reason().unwrap_or(DeadReason::Expired);
                session.kill(reason);
                return reason;
            };
            tokio::time::sleep_until(tokio::time::Instant::from_std(due)).await;
            if session.is_alive() {
                // Outcomes are recorded on the session and drive the next due time.
                let _ = self.heartbeat(session).await;
            }
        }
    }

    /// Fetch the signed manifest for `product`/`version` and the artifact
    /// key unwrapped under this session's key. The manifest is verified and
    /// must name the requested release. A kill verdict ends `session`.
    pub async fn fetch_manifest(
        &self,
        session: &ClientSession,
        product: &str,
        version: &str,
    ) -> Result<(SignedManifest, Zeroizing<[u8; 32]>), ClientError> {
        session.authorize()?;
        let result = self.request_manifest(session, product, version).await;
        settle(session, result)
    }

    async fn request_manifest(
        &self,
        session: &ClientSession,
        product: &str,
        version: &str,
    ) -> Result<(SignedManifest, Zeroizing<[u8; 32]>), ClientError> {
        let challenge = Challenge::new();
        let issued_at = session.now();
        let context = mac_context::payload(product, version);
        let request = PayloadRequest {
            session_id: session.session_id(),
            product: product.to_owned(),
            version: version.to_owned(),
            nonce: challenge.nonce,
            issued_at,
            mac: session.mac(&challenge.nonce, issued_at, &context)?,
        };
        request.validate()?;
        let env: Envelope =
            accept_json(self.transport.post(paths::PAYLOAD, &request).await?).await?;
        self.verify(
            &env,
            &Expectation {
                challenge: &challenge,
                session_id: &session.session_id(),
                audience: AUDIENCE_APP,
                operation: OP_PAYLOAD_FETCH,
                now: session.now(),
            },
        )?;
        let body: PayloadBody = parse_json(&env.body, "payload body")?;
        {
            let issuers = self.issuers();
            let manifest = body
                .manifest
                .verify(&issuers, session.now())
                .map_err(ClientError::InvalidResponse)?;
            if manifest.product != product || manifest.version != version {
                return Err(invalid("manifest names another release"));
            }
        }
        let key = session.unwrap_artifact_key(&challenge.nonce, &body.payload_key_wrap)?;
        let clock =
            SessionClock::from_response(body.server_time, challenge.minted, env.expires_at)?;
        session.consume(challenge.nonce, env.expires_at)?;
        session.set_clock(clock);
        self.apply_revocations(&body.revoked_key_ids);
        Ok((body.manifest, key))
    }

    /// Fetch the manifest once, download the sealed artifact, decrypt it,
    /// and check its sha256 against the manifest off the async runtime.
    /// Unverified bytes are never returned. A kill verdict ends `session`.
    pub async fn download_payload(
        &self,
        session: &ClientSession,
        product: &str,
        version: &str,
    ) -> Result<Payload, ClientError> {
        let (manifest, key) = self.fetch_manifest(session, product, version).await?;
        session.authorize()?;
        let result = self.download_sealed(session, product, version).await;
        let sealed = settle(session, result)?;
        let verified = tokio::task::spawn_blocking(move || {
            let mut plaintext =
                decrypt_artifact(&key, &sealed).map_err(ClientError::InvalidResponse)?;
            manifest
                .manifest
                .verify_payload(&plaintext)
                .map_err(ClientError::InvalidResponse)?;
            Ok(Payload {
                manifest,
                bytes: std::mem::take(&mut *plaintext),
            })
        })
        .await;
        match verified {
            Ok(result) => result,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => Err(ClientError::Core(KeystoneError::Io(std::io::Error::other(
                e,
            )))),
        }
    }

    async fn download_sealed(
        &self,
        session: &ClientSession,
        product: &str,
        version: &str,
    ) -> Result<Vec<u8>, ClientError> {
        validate_release(product, version)?;
        let nonce = Challenge::new().nonce;
        let issued_at = session.now();
        let authorization = DownloadAuthorization {
            session_id: session.session_id(),
            nonce,
            issued_at,
            mac: session.mac(&nonce, issued_at, &mac_context::download(product, version))?,
        };
        let resp = self
            .transport
            .download(&paths::download(product, version), &authorization.encode())
            .await?;
        if !resp.status().is_success() {
            return Err(rejection(resp).await);
        }
        read_capped(resp, MAX_ARTIFACT_BYTES).await
    }

    fn verify(&self, env: &Envelope, expect: &Expectation<'_>) -> Result<(), ClientError> {
        env.verify(&self.issuers(), expect)
            .map_err(ClientError::InvalidResponse)
    }

    /// Apply revocations announced inside a verified body.
    fn apply_revocations(&self, key_ids: &[u8]) {
        if key_ids.is_empty() {
            return;
        }
        let mut issuers = self.issuers_mut();
        for &key_id in key_ids {
            issuers.revoke(key_id);
        }
    }

    // A poisoned lock is recovered: the set only shrinks, so a panic
    // mid-revoke leaves it at worst stricter.
    fn issuers(&self) -> RwLockReadGuard<'_, TrustedIssuers> {
        self.issuers.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn issuers_mut(&self) -> RwLockWriteGuard<'_, TrustedIssuers> {
        self.issuers.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Apply a failed non-heartbeat request's verdict: only kills touch the
/// session.
fn settle<T>(session: &ClientSession, result: Result<T, ClientError>) -> Result<T, ClientError> {
    if let Err(e) = &result {
        session.request_failed(failure_verdict(e));
    }
    result
}

/// What a failed request means for the session. Rejections follow their
/// error code; lost or unverifiable responses are transient; local errors
/// leave the session alone.
fn failure_verdict(error: &ClientError) -> Verdict {
    match error {
        ClientError::ServerRejected { code, .. } => session_verdict(*code),
        ClientError::Transport(_)
        | ClientError::Stalled { .. }
        | ClientError::InvalidResponse(_) => Verdict::Transient,
        ClientError::Core(_)
        | ClientError::NotAuthenticated
        | ClientError::InvalidConfig { .. } => Verdict::RequestError,
    }
}

fn invalid(what: &str) -> ClientError {
    ClientError::InvalidResponse(KeystoneError::Malformed(what.to_owned()))
}

#[cfg(test)]
mod tests {
    use keystone_core::Issuer;

    use super::*;

    fn issuers() -> TrustedIssuers {
        TrustedIssuers::single(1, Issuer::generate(1).verifying_key())
    }

    #[test]
    fn builder_requires_https_unless_insecure_http_allowed() {
        let plaintext = KeystoneClient::builder("http://127.0.0.1:8443", issuers()).build();
        assert!(matches!(plaintext, Err(ClientError::InvalidConfig { .. })));

        let allowed = KeystoneClient::builder("http://127.0.0.1:8443", issuers())
            .allow_insecure_http()
            .build();
        assert!(allowed.is_ok());

        let pinned_plaintext = KeystoneClient::builder("http://127.0.0.1:8443", issuers())
            .allow_insecure_http()
            .pin_spki([0; 32])
            .build();
        assert!(matches!(
            pinned_plaintext,
            Err(ClientError::InvalidConfig { .. })
        ));

        assert!(
            KeystoneClient::builder("https://127.0.0.1:8443", issuers())
                .pin_spki([0; 32])
                .build()
                .is_ok()
        );
    }

    #[test]
    fn config_errors_keep_their_source() {
        let err = KeystoneClient::builder("https://127.0.0.1:8443", issuers())
            .server_ca_pem("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")
            .build()
            .unwrap_err();
        assert!(matches!(
            &err,
            ClientError::InvalidConfig {
                source: Some(_),
                ..
            }
        ));
        assert!(std::error::Error::source(&err).is_some());
    }
}
