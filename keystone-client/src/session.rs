//! Client-side sessions: the key material, the lease state machine judged
//! on a monotonic session clock, and the cheap [`SessionGate`] a payload
//! consults before every protected operation.

use std::fmt;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, Utc};
use keystone_core::wire::Verdict;
use keystone_core::{
    ConsumedSet, DeadReason, FeatureGrant, HandoffPayload, HandoffToken, KeyWrap, KeystoneError,
    Lease, RequestBinding, SessionState, mac_request, unwrap_artifact_key,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ClientError;

/// First retry delay after a failed heartbeat; doubles per attempt.
const RETRY_BASE: StdDuration = StdDuration::from_secs(1);
/// Ceiling on a single retry delay.
const RETRY_CAP: StdDuration = StdDuration::from_secs(30);
/// Shortest interval between two renewals.
const MIN_RENEW_INTERVAL: Duration = Duration::seconds(5);
/// Longest single sleep the clock maps a deadline to.
const MAX_SLEEP: StdDuration = StdDuration::from_secs(24 * 60 * 60);

/// Server time as this process best knows it: a server timestamp taken
/// from a signed body, advanced by the monotonic clock. Wall-clock
/// changes on this machine never move it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionClock {
    anchor: Instant,
    server_at_anchor: DateTime<Utc>,
}

impl SessionClock {
    /// A clock reading `server_now` at this instant.
    pub(crate) fn starting_at(server_now: DateTime<Utc>) -> Self {
        Self::anchored(Instant::now(), server_now)
    }

    fn anchored(anchor: Instant, server_at_anchor: DateTime<Utc>) -> Self {
        Self {
            anchor,
            server_at_anchor,
        }
    }

    /// Current server-aligned time.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.at(Instant::now())
    }

    fn at(&self, instant: Instant) -> DateTime<Utc> {
        let elapsed = Duration::from_std(instant.saturating_duration_since(self.anchor))
            .unwrap_or(Duration::MAX);
        self.server_at_anchor
            .checked_add_signed(elapsed)
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
    }

    /// The monotonic instant at which this clock reads `t`.
    fn instant_at(&self, t: DateTime<Utc>) -> Instant {
        let delta = t - self.server_at_anchor;
        match delta.to_std() {
            Ok(ahead) => self.anchor + ahead.min(MAX_SLEEP),
            Err(_) => {
                let behind = (-delta).to_std().unwrap_or(StdDuration::ZERO);
                self.anchor.checked_sub(behind).unwrap_or(self.anchor)
            }
        }
    }
}

/// Pending heartbeat retry after a failure.
#[derive(Debug, Clone, Copy)]
struct Retry {
    attempts: u32,
    at: Instant,
}

/// Everything mutable about a session, behind one lock that is never held
/// across an await.
struct State {
    key: Option<Zeroizing<[u8; 32]>>,
    lease: SessionState,
    features: Vec<FeatureGrant>,
    clock: SessionClock,
    consumed: ConsumedSet,
    retry: Option<Retry>,
    /// Longest lease the session has held; sets the renewal floor.
    lease_len: Duration,
    /// The last renewal did not move `expires_at`: renewing is pointless.
    capped: bool,
}

impl State {
    fn dead_reason(&self) -> Option<DeadReason> {
        dead_reason_at(&self.lease, self.clock.now())
    }

    fn kill(&mut self, reason: DeadReason) {
        self.key = None;
        self.lease.kill(reason);
    }
}

/// Why `state` no longer authorizes at `now`, including a lapsed lease or
/// grace deadline that has not been recorded as a kill yet.
fn dead_reason_at(state: &SessionState, now: DateTime<Utc>) -> Option<DeadReason> {
    if let SessionState::Dead { reason } = state {
        return Some(*reason);
    }
    match state.authorize(now) {
        Ok(()) => None,
        Err(KeystoneError::GraceExhausted) => Some(DeadReason::GraceExhausted),
        Err(_) => Some(DeadReason::Expired),
    }
}

fn lease_len(lease: &Lease) -> Duration {
    lease.expires_at - lease.granted_at
}

struct Inner {
    session_id: Uuid,
    product: String,
    state: RwLock<State>,
}

impl Inner {
    // A poisoned lock still holds a consistent state: every writer replaces
    // whole values.
    fn read(&self) -> RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A read-only, network-free view of a session's authorization, cheap to
/// clone into every thread of a payload. Reflects each lease the session
/// installs and each kill it records.
#[derive(Clone)]
pub struct SessionGate {
    inner: Arc<Inner>,
}

impl SessionGate {
    /// `Ok` while the session is alive and its lease (or grace window) is
    /// valid on the session clock; otherwise `NotAuthenticated`.
    pub fn authorize(&self) -> Result<(), ClientError> {
        match self.dead_reason() {
            None => Ok(()),
            Some(_) => Err(ClientError::NotAuthenticated),
        }
    }

    /// True when the session is authorized and holds a grant for `name`
    /// that has not expired on the session clock.
    pub fn has_feature(&self, name: &str) -> bool {
        let state = self.inner.read();
        let now = state.clock.now();
        dead_reason_at(&state.lease, now).is_none()
            && state
                .features
                .iter()
                .any(|grant| grant.feature == name && grant.is_active(now))
    }

    /// Whether [`SessionGate::authorize`] would succeed.
    pub fn is_alive(&self) -> bool {
        self.dead_reason().is_none()
    }

    /// Why the session no longer authorizes, if it does not.
    pub fn dead_reason(&self) -> Option<DeadReason> {
        self.inner.read().dead_reason()
    }
}

impl fmt::Debug for SessionGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionGate")
            .field("session_id", &self.inner.session_id)
            .field("dead_reason", &self.dead_reason())
            .finish()
    }
}

/// A live session from [`crate::KeystoneClient::exchange`] or
/// [`crate::KeystoneClient::attest`]. A cheap handle: clones share the key,
/// lease, and gate, so a keepalive task and request callers can hold the
/// same session. The key is wiped the moment the session dies; the server
/// stays authoritative.
#[derive(Clone)]
pub struct ClientSession {
    inner: Arc<Inner>,
}

impl ClientSession {
    pub(crate) fn new(
        session_id: Uuid,
        product: String,
        key: Zeroizing<[u8; 32]>,
        lease: Lease,
        features: Vec<FeatureGrant>,
        clock: SessionClock,
    ) -> Self {
        let state = State {
            key: Some(key),
            lease_len: lease_len(&lease),
            lease: SessionState::Active { lease },
            features,
            clock,
            consumed: ConsumedSet::new(),
            retry: None,
            capped: false,
        };
        Self {
            inner: Arc::new(Inner {
                session_id,
                product,
                state: RwLock::new(state),
            }),
        }
    }

    /// The server's id for this session.
    pub fn session_id(&self) -> Uuid {
        self.inner.session_id
    }

    /// The product this session is entitled to.
    pub fn product(&self) -> &str {
        &self.inner.product
    }

    /// A read-only gate sharing this session's state.
    pub fn gate(&self) -> SessionGate {
        SessionGate {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Like [`SessionGate::authorize`], and records the death when the lease
    /// or grace window has lapsed, wiping the session key.
    pub fn authorize(&self) -> Result<(), ClientError> {
        let mut state = self.inner.write();
        match state.dead_reason() {
            None => Ok(()),
            Some(reason) => {
                state.kill(reason);
                Err(ClientError::NotAuthenticated)
            }
        }
    }

    /// Whether the session still authorizes on the session clock.
    pub fn is_alive(&self) -> bool {
        self.dead_reason().is_none()
    }

    /// Why the session no longer authorizes, if it does not.
    pub fn dead_reason(&self) -> Option<DeadReason> {
        self.inner.read().dead_reason()
    }

    /// Feature grants from the most recent lease body.
    pub fn features(&self) -> Vec<FeatureGrant> {
        self.inner.read().features.clone()
    }

    /// When the next heartbeat should be sent. Normally 80% into the lease
    /// but no sooner than `max(5 s, longest lease / 10)` after it was
    /// granted; after a failure, the pending backoff retry. Once a renewal
    /// fails to extend the lease this is the lease expiry itself. Never later
    /// than the end of the lease or grace window; `None` once dead.
    pub fn next_heartbeat_due(&self) -> Option<Instant> {
        let state = self.inner.read();
        if state.dead_reason().is_some() {
            return None;
        }
        let (lease, stop) = match &state.lease {
            SessionState::Active { lease } => (lease, lease.expires_at),
            SessionState::Grace { lease, deadline } => (lease, (*deadline).min(lease.expires_at)),
            SessionState::Dead { .. } => return None,
        };
        let stop = state.clock.instant_at(stop);
        if state.capped {
            return Some(stop);
        }
        let due = match state.retry {
            Some(retry) => retry.at,
            None => {
                let floor = MIN_RENEW_INTERVAL.max(state.lease_len / 10);
                let interval = (lease_len(lease) * 4 / 5).max(floor);
                state.clock.instant_at(lease.granted_at + interval)
            }
        };
        Some(due.min(stop))
    }

    /// Current server-aligned time.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.inner.read().clock.now()
    }

    /// Server clock minus the local wall clock, handed to a child process.
    pub(crate) fn server_offset(&self) -> Duration {
        self.now() - Utc::now()
    }

    /// MAC a request under the session key; `NotAuthenticated` once the key
    /// is gone.
    pub(crate) fn mac(
        &self,
        nonce: &[u8; 32],
        issued_at: DateTime<Utc>,
        context: &[u8],
    ) -> Result<[u8; 32], ClientError> {
        let state = self.inner.read();
        let key = state.key.as_deref().ok_or(ClientError::NotAuthenticated)?;
        Ok(mac_request(
            key,
            &RequestBinding {
                session_id: &self.inner.session_id,
                nonce,
                issued_at,
                context,
            },
        ))
    }

    /// Unwrap an artifact key wrapped for this session and `nonce`.
    pub(crate) fn unwrap_artifact_key(
        &self,
        nonce: &[u8; 32],
        wrap: &KeyWrap,
    ) -> Result<Zeroizing<[u8; 32]>, ClientError> {
        let state = self.inner.read();
        let key = state.key.as_deref().ok_or(ClientError::NotAuthenticated)?;
        unwrap_artifact_key(key, nonce, wrap).map_err(ClientError::InvalidResponse)
    }

    /// Record an accepted envelope's challenge so the same response is never
    /// accepted twice.
    pub(crate) fn consume(
        &self,
        nonce: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), ClientError> {
        let mut state = self.inner.write();
        let now = state.clock.now();
        state.consumed.evict_expired(now);
        state
            .consumed
            .consume(nonce, expires_at, now)
            .map_err(ClientError::InvalidResponse)
    }

    /// Install a verified lease body: refresh the lease, features, and clock
    /// anchor and clear any retry. A grace window that lapsed while the
    /// request was in flight is not revived.
    pub(crate) fn install_lease(
        &self,
        lease: Lease,
        features: Vec<FeatureGrant>,
        server_time: DateTime<Utc>,
    ) {
        let mut state = self.inner.write();
        let now = state.clock.now();
        let previous_expiry = match &state.lease {
            SessionState::Active { lease } | SessionState::Grace { lease, .. } => {
                Some(lease.expires_at)
            }
            SessionState::Dead { .. } => None,
        };
        let expires_at = lease.expires_at;
        let len = lease_len(&lease);
        state.lease.on_heartbeat_ok(lease, now);
        if matches!(state.lease, SessionState::Dead { .. }) {
            state.key = None;
            return;
        }
        state.capped = previous_expiry.is_some_and(|previous| expires_at <= previous);
        state.lease_len = state.lease_len.max(len);
        state.features = features;
        state.clock = SessionClock::starting_at(server_time);
        state.retry = None;
    }

    /// Re-anchor the clock on a signed server time outside a lease body.
    pub(crate) fn observe_server_time(&self, server_time: DateTime<Utc>) {
        self.inner.write().clock = SessionClock::starting_at(server_time);
    }

    /// A heartbeat failed: kills end the session, transient failures start
    /// (or continue) grace, and both non-kill outcomes schedule a jittered,
    /// exponentially growing retry.
    pub(crate) fn heartbeat_failed(&self, verdict: Verdict) {
        let mut state = self.inner.write();
        match verdict {
            Verdict::Kill(reason) => return state.kill(reason),
            Verdict::Transient => {
                let now = state.clock.now();
                state.lease.on_transient_failure(now);
            }
            Verdict::RequestError => {}
        }
        let attempts = state
            .retry
            .map_or(1, |retry| retry.attempts.saturating_add(1));
        state.retry = Some(Retry {
            attempts,
            at: Instant::now() + retry_delay(attempts, rand::random::<f64>()),
        });
    }

    /// A non-heartbeat request was rejected: only kill verdicts touch the
    /// session.
    pub(crate) fn request_failed(&self, verdict: Verdict) {
        if let Verdict::Kill(reason) = verdict {
            self.kill(reason);
        }
    }

    /// End the session for good and wipe the key.
    pub(crate) fn kill(&self, reason: DeadReason) {
        self.inner.write().kill(reason);
    }
}

impl fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSession")
            .field("session_id", &self.inner.session_id)
            .field("product", &self.inner.product)
            .field("state", &self.inner.read().lease)
            .finish_non_exhaustive()
    }
}

/// Delay before retry `attempt` (1-based): `RETRY_BASE` doubled per
/// attempt up to `RETRY_CAP`, scaled into its upper half by `jitter` in
/// `[0, 1]`.
fn retry_delay(attempt: u32, jitter: f64) -> StdDuration {
    let doublings = attempt.saturating_sub(1).min(16);
    let ceiling = RETRY_BASE.saturating_mul(1 << doublings).min(RETRY_CAP);
    ceiling.mul_f64(0.5 + 0.5 * jitter.clamp(0.0, 1.0))
}

/// A child process's handoff, opened but not yet redeemed. Redeem it with
/// [`crate::KeystoneClient::attest`] to obtain the child's own session.
pub struct PendingSession {
    payload: HandoffPayload,
    process_id: String,
    clock: SessionClock,
}

impl PendingSession {
    /// Open `token` as `process_id`, the identity the child will attest
    /// under. Fails with `Core` when the token was sealed for another
    /// identity, tampered with, or has expired.
    pub fn from_handoff(token: HandoffToken, process_id: &str) -> Result<Self, ClientError> {
        let payload = token.open(process_id)?;
        let server_now = Duration::try_milliseconds(payload.server_offset_millis)
            .and_then(|offset| Utc::now().checked_add_signed(offset))
            .ok_or_else(|| KeystoneError::Malformed("handoff server offset".into()))?;
        Ok(Self {
            payload,
            process_id: process_id.to_owned(),
            clock: SessionClock::starting_at(server_now),
        })
    }

    /// The loader session that minted the handoff.
    pub fn parent_session_id(&self) -> Uuid {
        self.payload.parent_session_id
    }

    /// The product the child session will be for.
    pub fn product(&self) -> &str {
        &self.payload.product
    }

    /// The identity the handoff was opened as.
    pub fn process_id(&self) -> &str {
        &self.process_id
    }

    /// Last server instant at which the handoff can be redeemed.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.payload.expires_at
    }

    pub(crate) fn payload(&self) -> &HandoffPayload {
        &self.payload
    }

    pub(crate) fn clock(&self) -> SessionClock {
        self.clock
    }
}

impl fmt::Debug for PendingSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSession")
            .field("parent_session_id", &self.payload.parent_session_id)
            .field("product", &self.payload.product)
            .field("process_id", &self.process_id)
            .field("expires_at", &self.payload.expires_at)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use keystone_core::wire::ErrorCode;

    use super::*;
    use crate::error::session_verdict;

    fn lease_at(start: DateTime<Utc>, ttl_secs: i64, grace_secs: i64) -> Lease {
        Lease {
            session_id: Uuid::nil(),
            granted_at: start,
            expires_at: start + Duration::seconds(ttl_secs),
            grace_period: Duration::seconds(grace_secs),
        }
    }

    fn session_on(clock: SessionClock, lease: Lease, features: Vec<FeatureGrant>) -> ClientSession {
        ClientSession::new(
            Uuid::nil(),
            "app".into(),
            Zeroizing::new([0xAB; 32]),
            lease,
            features,
            clock,
        )
    }

    fn fresh_session(ttl_secs: i64, grace_secs: i64) -> ClientSession {
        let now = Utc::now();
        session_on(
            SessionClock::starting_at(now),
            lease_at(now, ttl_secs, grace_secs),
            Vec::new(),
        )
    }

    fn has_key(session: &ClientSession) -> bool {
        session.inner.read().key.is_some()
    }

    fn is_active(session: &ClientSession) -> bool {
        matches!(session.inner.read().lease, SessionState::Active { .. })
    }

    fn grace_deadline(session: &ClientSession) -> DateTime<Utc> {
        match &session.inner.read().lease {
            SessionState::Grace { deadline, .. } => *deadline,
            other => panic!("expected grace, got {other:?}"),
        }
    }

    fn instant_of(session: &ClientSession, t: DateTime<Utc>) -> Instant {
        session.inner.read().clock.instant_at(t)
    }

    #[test]
    fn session_clock_ignores_wall_clock() {
        let server = DateTime::from_timestamp(978_307_200, 0).unwrap();
        let anchor = Instant::now();
        let clock = SessionClock::anchored(anchor, server);
        assert_eq!(clock.at(anchor), server);
        assert_eq!(
            clock.at(anchor + StdDuration::from_secs(5)),
            server + Duration::seconds(5)
        );
        assert_eq!(
            clock.instant_at(server + Duration::seconds(90)),
            anchor + StdDuration::from_secs(90)
        );

        // The wall clock is decades past this lease; the session clock is not.
        let behind = session_on(
            SessionClock::starting_at(server),
            lease_at(server, 300, 60),
            Vec::new(),
        );
        assert!(behind.authorize().is_ok());
        assert!(behind.next_heartbeat_due().is_some());

        // The wall clock is decades before this lease's expiry; the session
        // clock is past it.
        let future = DateTime::from_timestamp(4_102_444_800, 0).unwrap();
        let ahead = session_on(
            SessionClock::starting_at(future),
            lease_at(future - Duration::seconds(301), 300, 60),
            Vec::new(),
        );
        assert!(matches!(
            ahead.authorize(),
            Err(ClientError::NotAuthenticated)
        ));
        assert_eq!(ahead.dead_reason(), Some(DeadReason::Expired));
        assert!(!has_key(&ahead));
    }

    #[test]
    fn gate_verdicts_across_active_grace_dead() {
        fn shareable<T: Clone + Send + Sync + 'static>(_: &T) {}

        let session = fresh_session(300, 60);
        shareable(&session);
        let gate = session.gate();
        shareable(&gate);
        assert!(gate.authorize().is_ok());
        assert!(gate.is_alive());
        assert_eq!(gate.dead_reason(), None);

        session.heartbeat_failed(Verdict::Transient);
        grace_deadline(&session);
        assert!(gate.authorize().is_ok());
        assert!(gate.is_alive());

        // Lapse the grace window on the session clock.
        {
            let mut state = session.inner.write();
            let past = state.clock.now() - Duration::seconds(1);
            if let SessionState::Grace { deadline, .. } = &mut state.lease {
                *deadline = past;
            }
        }
        assert!(matches!(
            gate.authorize(),
            Err(ClientError::NotAuthenticated)
        ));
        assert_eq!(gate.dead_reason(), Some(DeadReason::GraceExhausted));
        assert!(!gate.is_alive());
        assert!(session.authorize().is_err());
        assert!(!has_key(&session));
        assert_eq!(session.next_heartbeat_due(), None);

        let revoked = fresh_session(300, 60);
        let revoked_gate = revoked.clone().gate();
        revoked.heartbeat_failed(Verdict::Kill(DeadReason::Revoked));
        assert_eq!(revoked_gate.dead_reason(), Some(DeadReason::Revoked));
        assert!(revoked_gate.authorize().is_err());
        assert!(!has_key(&revoked));
    }

    #[test]
    fn has_feature_requires_live_session_and_unexpired_grant() {
        let now = Utc::now();
        let session = session_on(
            SessionClock::starting_at(now),
            lease_at(now, 300, 60),
            vec![
                FeatureGrant {
                    feature: "live".into(),
                    expires_at: now + Duration::seconds(60),
                },
                FeatureGrant {
                    feature: "lapsed".into(),
                    expires_at: now - Duration::seconds(1),
                },
            ],
        );
        let gate = session.gate();
        assert!(gate.has_feature("live"));
        assert!(!gate.has_feature("lapsed"));
        assert!(!gate.has_feature("absent"));

        session.kill(DeadReason::Revoked);
        assert!(!gate.has_feature("live"));
    }

    #[test]
    fn verdicts_come_from_error_codes_and_codeless_is_transient() {
        let codeless = ClientError::ServerRejected {
            status: 404,
            code: None,
            message: String::new(),
        };
        assert!(codeless.is_retryable());
        let session = fresh_session(300, 60);
        session.heartbeat_failed(session_verdict(None));
        assert!(session.is_alive());
        grace_deadline(&session);

        let unknown = ClientError::ServerRejected {
            status: 404,
            code: Some(ErrorCode::UnknownSession),
            message: String::new(),
        };
        assert!(!unknown.is_retryable());
        let session = fresh_session(300, 60);
        session.heartbeat_failed(session_verdict(Some(ErrorCode::UnknownSession)));
        assert_eq!(session.dead_reason(), Some(DeadReason::UnknownSession));

        let session = fresh_session(300, 60);
        session.heartbeat_failed(session_verdict(Some(ErrorCode::BadRequest)));
        assert!(is_active(&session));

        let rate_limited = ClientError::ServerRejected {
            status: 429,
            code: Some(ErrorCode::RateLimited),
            message: String::new(),
        };
        assert!(rate_limited.is_retryable());
        let session = fresh_session(300, 60);
        session.request_failed(session_verdict(Some(ErrorCode::RateLimited)));
        assert!(is_active(&session));
        session.request_failed(session_verdict(Some(ErrorCode::SessionRevoked)));
        assert_eq!(session.dead_reason(), Some(DeadReason::Revoked));
    }

    #[test]
    fn retry_backoff_doubles_to_thirty_seconds_and_stays_inside_grace() {
        let secs = |s: f64| StdDuration::from_secs_f64(s);
        let expected = [
            (1, 1.0, secs(1.0)),
            (1, 0.0, secs(0.5)),
            (2, 1.0, secs(2.0)),
            (3, 1.0, secs(4.0)),
            (5, 1.0, secs(16.0)),
            (5, 0.5, secs(12.0)),
            (6, 1.0, secs(30.0)),
            (6, 0.0, secs(15.0)),
            (40, 1.0, secs(30.0)),
        ];
        for (attempt, jitter, delay) in expected {
            assert_eq!(retry_delay(attempt, jitter), delay, "attempt {attempt}");
        }

        let session = fresh_session(300, 5);
        session.heartbeat_failed(Verdict::Transient);
        let deadline = instant_of(&session, grace_deadline(&session));
        for _ in 0..12 {
            let due = session.next_heartbeat_due().expect("alive in grace");
            assert!(due <= deadline);
            session.heartbeat_failed(Verdict::Transient);
        }
        assert_eq!(session.next_heartbeat_due(), Some(deadline));
    }

    #[test]
    fn renewal_respects_the_floor_and_stops_when_the_lease_stops_growing() {
        let now = Utc::now();
        let session = session_on(
            SessionClock::starting_at(now),
            lease_at(now, 100, 60),
            Vec::new(),
        );
        assert_eq!(
            session.next_heartbeat_due(),
            Some(instant_of(&session, now + Duration::seconds(80)))
        );

        // Near the grant's end a renewal extends the lease to only 12 s:
        // 80% is 9.6 s, below the floor of a tenth of the 100 s lease.
        let granted = now + Duration::seconds(95);
        session.install_lease(lease_at(granted, 12, 60), Vec::new(), granted);
        assert_eq!(
            session.next_heartbeat_due(),
            Some(instant_of(&session, granted + Duration::seconds(10)))
        );

        // A renewal that ends where the previous lease ended: sleep to expiry.
        let renewed = granted + Duration::seconds(10);
        let same_end = Lease {
            session_id: Uuid::nil(),
            granted_at: renewed,
            expires_at: granted + Duration::seconds(12),
            grace_period: Duration::seconds(60),
        };
        session.install_lease(same_end, Vec::new(), renewed);
        assert_eq!(
            session.next_heartbeat_due(),
            Some(instant_of(&session, granted + Duration::seconds(12)))
        );
    }
}
