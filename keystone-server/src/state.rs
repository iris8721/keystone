//! Shared application state and its builder.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use keystone_core::{BackendError, DeadReason, EntitlementSource, Issuer};
use parking_lot::{Mutex, RwLock};
use uuid::Uuid;

use crate::accounts::SecretVerifier;
use crate::audit::{AuditEvent, AuditSink, TracingAudit};
use crate::config::{AdminToken, PayloadConfig, RateLimits};
use crate::downloads::DownloadLog;
use crate::error::ServerError;
use crate::limiter::{MemoryLimiter, RateLimiter};
use crate::revocations::{MemoryRevocations, RevocationStore};
use crate::store::{MemoryStore, SessionStore};

/// How long a different HWID for the same account counts as an anomaly.
const HWID_WINDOW: Duration = Duration::minutes(10);
/// Bounded retries for a compare-and-swap that keeps losing.
pub(crate) const CAS_ATTEMPTS: usize = 16;

/// Last HWID hash an account presented, and when.
type Sighting = ([u8; 32], DateTime<Utc>);

/// Everything the routes share. Cheap to clone.
#[derive(Clone)]
pub struct AppState {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) issuer: Issuer,
    pub(crate) entitlements: Arc<dyn EntitlementSource>,
    pub(crate) store: Arc<dyn SessionStore>,
    pub(crate) limiter: Arc<dyn RateLimiter>,
    pub(crate) revocations: Arc<dyn RevocationStore>,
    pub(crate) audit: Arc<dyn AuditSink>,
    pub(crate) lease_ttl: Duration,
    pub(crate) grace_period: Duration,
    pub(crate) rate_limits: RateLimits,
    pub(crate) admin_token: Option<AdminToken>,
    pub(crate) admin_certificates: BTreeSet<[u8; 32]>,
    pub(crate) require_client_certificates: bool,
    pub(crate) payloads: Option<PayloadConfig>,
    pub(crate) downloads: Option<DownloadLog>,
    pub(crate) verifier: SecretVerifier,
    pub(crate) publish: Arc<tokio::sync::Mutex<()>>,
    revoked_key_ids: RwLock<BTreeSet<u8>>,
    key_revocation: tokio::sync::Mutex<()>,
    fingerprints: Mutex<HashMap<String, Sighting>>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("key_id", &self.inner.issuer.key_id())
            .field("lease_ttl", &self.inner.lease_ttl)
            .field("grace_period", &self.inner.grace_period)
            .field("rate_limits", &self.inner.rate_limits)
            .field(
                "require_client_certificates",
                &self.inner.require_client_certificates,
            )
            .field("payloads", &self.inner.payloads)
            .finish_non_exhaustive()
    }
}

/// Configures an [`AppState`]. Defaults: [`MemoryStore`], [`MemoryLimiter`],
/// [`MemoryRevocations`], [`TracingAudit`], 300 s leases, 60 s grace,
/// default rate limits, no admin token or allow-list, client certificates
/// optional, no payloads.
pub struct AppStateBuilder {
    issuer: Issuer,
    entitlements: Arc<dyn EntitlementSource>,
    store: Option<Arc<dyn SessionStore>>,
    limiter: Option<Arc<dyn RateLimiter>>,
    revocations: Option<Arc<dyn RevocationStore>>,
    audit: Option<Arc<dyn AuditSink>>,
    lease_ttl: Duration,
    grace_period: Duration,
    rate_limits: RateLimits,
    admin_token: Option<AdminToken>,
    admin_certificates: BTreeSet<[u8; 32]>,
    require_client_certificates: bool,
    payloads: Option<PayloadConfig>,
    download_log: Option<PathBuf>,
    revoked_key_ids: BTreeSet<u8>,
}

impl std::fmt::Debug for AppStateBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStateBuilder")
            .field("key_id", &self.issuer.key_id())
            .field("lease_ttl", &self.lease_ttl)
            .field("grace_period", &self.grace_period)
            .field("rate_limits", &self.rate_limits)
            .field("admin_token", &self.admin_token)
            .field("admin_certificates", &self.admin_certificates.len())
            .field(
                "require_client_certificates",
                &self.require_client_certificates,
            )
            .field("payloads", &self.payloads)
            .field("download_log", &self.download_log)
            .field("revoked_key_ids", &self.revoked_key_ids)
            .finish_non_exhaustive()
    }
}

impl AppStateBuilder {
    /// Session storage.
    pub fn session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Rate limiter.
    pub fn rate_limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.limiter = Some(limiter);
        self
    }

    /// Durable store for revoked key ids; loaded by [`Self::build`].
    pub fn revocations(mut self, revocations: Arc<dyn RevocationStore>) -> Self {
        self.revocations = Some(revocations);
        self
    }

    /// Audit sink.
    pub fn audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Lease lifetime per grant or renewal; must be positive.
    pub fn lease_ttl(mut self, ttl: Duration) -> Self {
        self.lease_ttl = ttl;
        self
    }

    /// Grace a client may run on after a transient failure; must not be negative.
    pub fn grace_period(mut self, grace: Duration) -> Self {
        self.grace_period = grace;
        self
    }

    /// Per-minute ceilings.
    pub fn rate_limits(mut self, limits: RateLimits) -> Self {
        self.rate_limits = limits;
        self
    }

    /// Credential for the admin router; without one every admin request is
    /// 403 `forbidden`.
    pub fn admin_token(mut self, token: AdminToken) -> Self {
        self.admin_token = Some(token);
        self
    }

    /// sha256 of the leaf certificates allowed on the admin router. When
    /// non-empty, any other certificate (or none) is 403 `forbidden`.
    pub fn admin_certificates(mut self, hashes: BTreeSet<[u8; 32]>) -> Self {
        self.admin_certificates = hashes;
        self
    }

    /// Whether every request must carry client certificates (as attached by
    /// [`crate::tls::PeerCertAcceptor`]); a request without them is refused
    /// with 500 instead of being served unbound.
    pub fn require_client_certificates(mut self, required: bool) -> Self {
        self.require_client_certificates = required;
        self
    }

    /// Enable the payload routes and artifact publishing.
    pub fn payloads(mut self, payloads: PayloadConfig) -> Self {
        self.payloads = Some(payloads);
        self
    }

    /// Append download records to `path`; requires [`Self::payloads`].
    pub fn download_log(mut self, path: PathBuf) -> Self {
        self.download_log = Some(path);
        self
    }

    /// Issuer key ids revoked in addition to what the revocation store holds.
    pub fn revoked_key_ids(mut self, ids: BTreeSet<u8>) -> Self {
        self.revoked_key_ids = ids;
        self
    }

    /// Load revocations and open the download log. Fails with
    /// [`ServerError::ActiveKeyRevoked`] when the issuer's own key id is
    /// revoked, and with `Config` naming the builder method for an invalid
    /// setting (including an admin token with required client certificates
    /// but no `admin_certificates`).
    pub async fn build(self) -> Result<AppState, ServerError> {
        if self.lease_ttl <= Duration::zero() {
            return Err(ServerError::config("lease_ttl", "must be positive"));
        }
        if self.grace_period < Duration::zero() {
            return Err(ServerError::config("grace_period", "must not be negative"));
        }
        if self.rate_limits.window.is_zero() {
            return Err(ServerError::config(
                "rate_limits",
                "window must be positive",
            ));
        }
        if self.admin_token.is_some()
            && self.require_client_certificates
            && self.admin_certificates.is_empty()
        {
            return Err(ServerError::config(
                "admin_certificates",
                "required with an admin token when client certificates are required",
            ));
        }
        let revocations = self
            .revocations
            .unwrap_or_else(|| Arc::new(MemoryRevocations::new()));
        let mut revoked = self.revoked_key_ids;
        revoked.extend(revocations.load().await.map_err(ServerError::Revocations)?);
        if revoked.contains(&self.issuer.key_id()) {
            return Err(ServerError::ActiveKeyRevoked(self.issuer.key_id()));
        }
        let downloads = match (&self.download_log, &self.payloads) {
            (Some(path), Some(payloads)) => Some(
                DownloadLog::open(path, &payloads.watermark_secret).map_err(|e| {
                    ServerError::config("download_log", format!("{}: {e}", path.display()))
                })?,
            ),
            (Some(_), None) => {
                return Err(ServerError::config("download_log", "requires payloads"));
            }
            (None, _) => None,
        };
        Ok(AppState {
            inner: Arc::new(Inner {
                issuer: self.issuer,
                entitlements: self.entitlements,
                store: self.store.unwrap_or_else(|| Arc::new(MemoryStore::new())),
                limiter: self
                    .limiter
                    .unwrap_or_else(|| Arc::new(MemoryLimiter::new())),
                revocations,
                audit: self.audit.unwrap_or_else(|| Arc::new(TracingAudit)),
                lease_ttl: self.lease_ttl,
                grace_period: self.grace_period,
                rate_limits: self.rate_limits,
                admin_token: self.admin_token,
                admin_certificates: self.admin_certificates,
                require_client_certificates: self.require_client_certificates,
                payloads: self.payloads,
                downloads,
                verifier: SecretVerifier::new(),
                publish: Arc::new(tokio::sync::Mutex::new(())),
                revoked_key_ids: RwLock::new(revoked),
                key_revocation: tokio::sync::Mutex::new(()),
                fingerprints: Mutex::new(HashMap::new()),
            }),
        })
    }
}

impl AppState {
    /// Start configuring a state around the signing key and entitlement backend.
    pub fn builder(issuer: Issuer, entitlements: Arc<dyn EntitlementSource>) -> AppStateBuilder {
        AppStateBuilder {
            issuer,
            entitlements,
            store: None,
            limiter: None,
            revocations: None,
            audit: None,
            lease_ttl: Duration::seconds(300),
            grace_period: Duration::seconds(60),
            rate_limits: RateLimits::default(),
            admin_token: None,
            admin_certificates: BTreeSet::new(),
            require_client_certificates: false,
            payloads: None,
            download_log: None,
            revoked_key_ids: BTreeSet::new(),
        }
    }

    /// Issuer key ids clients must stop trusting, ascending.
    pub fn revoked_key_ids(&self) -> Vec<u8> {
        self.inner.revoked_key_ids.read().iter().copied().collect()
    }

    /// Revoke a session and, transitively, every child attested from it.
    /// Returns how many live sessions were killed; an unknown id is `Ok(0)`.
    pub async fn revoke_session(&self, session_id: Uuid) -> Result<u64, ServerError> {
        let killed = self.kill_trees([session_id]).await?;
        if killed > 0 {
            self.audit(AuditEvent::SessionRevoked { session_id });
        }
        Ok(killed)
    }

    /// Revoke every session of `account` and all their descendants. An
    /// exchange racing this call is revoked as well.
    pub async fn revoke_account(&self, account: &str) -> Result<u64, ServerError> {
        let store = &self.inner.store;
        store
            .bump_account_epoch(account)
            .await
            .map_err(ServerError::Store)?;
        let ids = store
            .ids_for_account(account)
            .await
            .map_err(ServerError::Store)?;
        let killed = self.kill_trees(ids).await?;
        self.audit(AuditEvent::AccountRevoked {
            account: account.to_string(),
            sessions: killed,
        });
        Ok(killed)
    }

    /// Revoke an issuer key id: persist it, publish it to clients, and kill
    /// every session and its descendants. The active signing key cannot be
    /// revoked ([`ServerError::ActiveKeyRevoked`]); nothing is applied unless
    /// the revocation store accepted it.
    pub async fn revoke_key_id(&self, key_id: u8) -> Result<u64, ServerError> {
        if key_id == self.inner.issuer.key_id() {
            return Err(ServerError::ActiveKeyRevoked(key_id));
        }
        let _serial = self.inner.key_revocation.lock().await;
        self.inner
            .revocations
            .persist(key_id)
            .await
            .map_err(ServerError::Revocations)?;
        self.inner.revoked_key_ids.write().insert(key_id);
        let ids = self
            .inner
            .store
            .all_ids()
            .await
            .map_err(ServerError::Store)?;
        let killed = self.kill_trees(ids).await?;
        self.audit(AuditEvent::KeyRevoked {
            key_id,
            sessions: killed,
        });
        Ok(killed)
    }

    /// Drop expired sessions, handoffs, nonces, limiter buckets, and HWID
    /// sightings. [`crate::serve()`] runs this every 30 s; embedders serving the
    /// routers themselves call it on their own timer.
    pub async fn sweep(&self) -> Result<usize, ServerError> {
        let now = Utc::now();
        self.inner.limiter.evict(std::time::Instant::now()).await;
        self.inner
            .fingerprints
            .lock()
            .retain(|_, (_, seen)| now - *seen < HWID_WINDOW);
        self.inner
            .store
            .sweep(now)
            .await
            .map_err(ServerError::Store)
    }

    pub(crate) fn audit(&self, event: AuditEvent) {
        self.inner.audit.record(event);
    }

    /// Record an HWID sighting; true when the account presented a different
    /// fingerprint inside the window.
    pub(crate) fn hwid_anomaly(
        &self,
        account: &str,
        hwid_hash: [u8; 32],
        now: DateTime<Utc>,
    ) -> bool {
        let mut seen = self.inner.fingerprints.lock();
        let anomalous = seen
            .get(account)
            .is_some_and(|(prev, at)| *prev != hwid_hash && now - *at < HWID_WINDOW);
        seen.insert(account.to_string(), (hwid_hash, now));
        anomalous
    }

    /// Kill each root, then its children breadth-first. A child inserted
    /// after its parent died is caught by attest's post-insert parent check.
    async fn kill_trees(&self, roots: impl IntoIterator<Item = Uuid>) -> Result<u64, ServerError> {
        let mut killed = 0;
        let mut pending: VecDeque<Uuid> = roots.into_iter().collect();
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            if self.kill(&id, DeadReason::Revoked).await? {
                killed += 1;
            }
            pending.extend(
                self.inner
                    .store
                    .children_of(&id)
                    .await
                    .map_err(ServerError::Store)?,
            );
        }
        Ok(killed)
    }

    /// Mark a session dead; false when it is unknown or already dead.
    pub(crate) async fn kill(&self, id: &Uuid, reason: DeadReason) -> Result<bool, ServerError> {
        kill_session(self.inner.store.as_ref(), id, reason)
            .await
            .map_err(ServerError::Store)
    }
}

pub(crate) async fn kill_session(
    store: &dyn SessionStore,
    id: &Uuid,
    reason: DeadReason,
) -> Result<bool, BackendError> {
    for _ in 0..CAS_ATTEMPTS {
        let Some((mut record, version)) = store.get(id).await? else {
            return Ok(false);
        };
        if record.dead.is_some() {
            return Ok(false);
        }
        record.dead = Some(reason);
        if store.replace(id, version, record).await? {
            return Ok(true);
        }
        tokio::task::yield_now().await;
    }
    Err("session update kept conflicting".into())
}
