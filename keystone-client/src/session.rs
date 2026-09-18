//! Client-side session: the material and state an exchange produces.
//!
//! The session key is the only thing that proves possession to the
//! server — it is never serialized, never logged, and dropped the
//! moment the session dies so a dead session cannot mint MACs.

use std::fmt;

use chrono::{DateTime, Duration, Utc};
use keystone_core::{
    ConsumedSet, DeadReason, Handoff, HandoffPayload, KeystoneError, Lease, Manifest,
    SessionState,
};
use uuid::Uuid;

use crate::error::ClientError;

/// A live session produced by `KeystoneClient::exchange`.
///
/// Owns the session key and the local `SessionState` mirror. The
/// server is authoritative — this state only decides whether the app
/// may keep running between heartbeats.
pub struct ClientSession {
    session_id: Uuid,
    /// `None` once the session is dead: kill drops the key so no
    /// further attest/heartbeat MAC can ever be produced from it.
    session_key: Option<[u8; 32]>,
    /// The issuer verifying key the exchange was verified against.
    /// Sealed into handoffs so the app pins the same key without
    /// trusting an unauthenticated channel for it.
    server_pubkey: [u8; 32],
    state: SessionState,
    /// Response nonces this session already accepted. A replayed
    /// envelope carries a nonce we've seen — rejected even if it still
    /// verifies cryptographically.
    consumed: ConsumedSet,
    /// Latest observed offset between server clock and ours, from the
    /// server_time field in signed bodies. Every freshness judgment
    /// this session makes runs on drift-adjusted time — a skewed
    /// local clock must not misjudge an envelope or a deadline.
    clock_drift: chrono::Duration,
    /// Sessions opened from a handoff have not yet performed the
    /// application's own attestation (DESIGN.md step 6). Until
    /// `attest` succeeds, no session-bound operation may run — the
    /// app cannot skip proving itself to the server.
    pending_attest: bool,
}

impl ClientSession {
    /// Build a session from a verified exchange. `lease` becomes the
    /// initial Active state.
    pub(crate) fn new(
        session_id: Uuid,
        session_key: [u8; 32],
        lease: Lease,
        server_pubkey: [u8; 32],
    ) -> Self {
        Self {
            session_id,
            session_key: Some(session_key),
            server_pubkey,
            state: SessionState::Active { lease },
            consumed: ConsumedSet::new(),
            clock_drift: chrono::Duration::zero(),
            // The launcher authenticated itself at exchange — only
            // handoff sessions carry the pending gate.
            pending_attest: false,
        }
    }

    /// Record the offset between the server's clock and ours. Called
    /// with the server_time from each signed body.
    pub(crate) fn observe_server_time(&mut self, server_time: DateTime<Utc>) {
        self.clock_drift = server_time - Utc::now();
    }

    /// The last observed server-minus-local clock offset.
    pub fn clock_drift(&self) -> chrono::Duration {
        self.clock_drift
    }

    /// Drift-adjusted current time: the server's clock as best we know
    /// it. Freshness checks run on this so a skewed local clock can
    /// neither stretch a live envelope nor shorten a grace window.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        Utc::now() + self.clock_drift
    }

    /// Whether this session still owes the server its own attestation.
    pub(crate) fn is_pending_attest(&self) -> bool {
        self.pending_attest
    }

    /// Called by `KeystoneClient::attest` after the attested lease is
    /// verified and installed — the gate lifts only on success.
    pub(crate) fn clear_pending_attest(&mut self) {
        self.pending_attest = false;
    }

    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// The session key, or `MissingSessionKey` once the session is
    /// dead and the material dropped.
    pub(crate) fn session_key(&self) -> Result<&[u8; 32], ClientError> {
        self.session_key.as_ref().ok_or(ClientError::MissingSessionKey)
    }

    /// May protected operations run right now? Judges on
    /// drift-adjusted time and owns the consequences: an Expired or
    /// GraceExhausted verdict kills the session and drops the key —
    /// "grace exhausted → clear session material" (DESIGN.md step 9).
    /// A handoff session that hasn't attested yet is NotAuthenticated
    /// regardless of what its lease says.
    pub fn authorize(&mut self) -> Result<(), ClientError> {
        let verdict = self.state.authorize(self.now());
        match verdict {
            Err(KeystoneError::GraceExhausted) => {
                self.kill(DeadReason::GraceExhausted);
                Err(ClientError::GraceExhausted)
            }
            Err(KeystoneError::Expired) => {
                self.kill(DeadReason::Expired);
                Err(ClientError::Core(KeystoneError::Expired))
            }
            Err(e) => Err(ClientError::Core(e)),
            Ok(()) if self.pending_attest => Err(ClientError::NotAuthenticated),
            Ok(()) => Ok(()),
        }
    }

    /// True while the session is Active or in Grace — i.e. a heartbeat
    /// could still succeed. Dead is final.
    pub fn is_alive(&self) -> bool {
        !matches!(self.state, SessionState::Dead { .. })
    }

    /// When the next heartbeat should fire: ~80% through the current
    /// lease window, so a renewal lands well before expiry and leaves
    /// room for a retry. In Grace the deadline is the hard stop — the
    /// result is clamped to it so a caller sleeping until `due` always
    /// wakes inside the grace window. `None` for a dead session; never
    /// returns a time in the past.
    ///
    /// The caller owns the loop — this only reports the deadline.
    pub fn next_heartbeat_due(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let (lease, deadline) = match &self.state {
            SessionState::Active { lease } => (lease, None),
            SessionState::Grace { lease, deadline } => (lease, Some(*deadline)),
            SessionState::Dead { .. } => return None,
        };
        let window = lease.expires_at - lease.granted_at;
        let mut due =
            lease.granted_at + Duration::milliseconds(window.num_milliseconds() * 4 / 5);
        if let Some(deadline) = deadline {
            due = due.min(deadline);
        }
        Some(due.max(now))
    }

    /// Record a nonce this session accepted, so a replayed envelope is
    /// rejected even when it still verifies. The exchange envelope's
    /// nonce is consumed at construction; the app calls this for any
    /// further envelopes it accepts on this session.
    pub fn consume_nonce(
        &mut self,
        nonce: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<(), KeystoneError> {
        self.consumed.consume(nonce, expires_at)
    }

    /// Whether a nonce was already accepted by this session.
    pub fn is_nonce_consumed(&self, nonce: &[u8; 32]) -> bool {
        self.consumed.is_consumed(nonce)
    }

    /// Whether a manifest grants `name` right now. Convenience over
    /// `Manifest::has_feature` — it reports the grant only; whether the
    /// session itself may run protected operations is `authorize`'s
    /// call.
    pub fn has_feature(&self, manifest: &Manifest, name: &str, now: DateTime<Utc>) -> bool {
        manifest.has_feature(name, now)
    }

    /// The issuer verifying key this session was established under —
    /// the key the app must pin when it builds its own client.
    pub fn server_pubkey(&self) -> [u8; 32] {
        self.server_pubkey
    }

    /// Produce the encrypted handoff for the application this client
    /// is about to launch (DESIGN.md step 5).
    ///
    /// Returns the sealed blob plus the freshly generated handoff key.
    /// The blob carries only what the app needs to attest — session
    /// id, session key, lease, pinned issuer key — and the caller
    /// delivers the key to the child through the launch channel (env
    /// var, argv, shared memory). Without it the blob is AEAD-sealed
    /// noise; with it, only the intended `process_id` can open it —
    /// a name-level binding to a claimed identity, not OS-verified
    /// process identity.
    ///
    /// A dead session cannot mint a handoff — its key is already gone.
    /// `ttl` is clamped to `MAX_HANDOFF_TTL`: a handoff is a
    /// launch-time event, not a stored credential, so a caller asking
    /// for days gets minutes.
    pub fn make_handoff(
        &self,
        process_id: &str,
        ttl: Duration,
    ) -> Result<(Handoff, [u8; 32]), ClientError> {
        const MAX_HANDOFF_TTL: Duration = Duration::minutes(5);
        let ttl = ttl.min(MAX_HANDOFF_TTL);
        let (session_key, lease) = match &self.state {
            SessionState::Active { lease } => (self.session_key()?, lease.clone()),
            // A handoff minted inside grace must die with the client's
            // grace window — the sealed lease never authorizes past
            // the deadline the first failure fixed.
            SessionState::Grace { lease, deadline } => {
                let mut lease = lease.clone();
                lease.expires_at = lease.expires_at.min(*deadline);
                (self.session_key()?, lease)
            }
            SessionState::Dead { .. } => return Err(ClientError::NotAuthenticated),
        };
        let mut handoff_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut handoff_key);
        let blob = Handoff::seal(
            &handoff_key,
            &HandoffPayload {
                session_id: self.session_id,
                session_key: *session_key,
                lease,
                server_pubkey: self.server_pubkey,
            },
            process_id,
            ttl,
        )?;
        Ok((blob, handoff_key))
    }

    /// The application side of the handoff: open the blob with the key
    /// the launcher delivered, and get a live session ready to attest.
    ///
    /// This is how the payload obtains session material without ever
    /// seeing credentials — it still must prove session-key possession
    /// to the server itself via `KeystoneClient::attest`.
    pub fn from_handoff(
        handoff_key: &[u8; 32],
        blob: &Handoff,
        process_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, ClientError> {
        let payload = blob.open(handoff_key, process_id, now)?;
        Ok(Self {
            session_id: payload.session_id,
            session_key: Some(payload.session_key),
            server_pubkey: payload.server_pubkey,
            state: SessionState::Active {
                lease: payload.lease,
            },
            consumed: ConsumedSet::new(),
            clock_drift: chrono::Duration::zero(),
            // The app still owes the server its own attestation —
            // opening the blob proves launch-channel possession, not
            // session-key possession to the server.
            pending_attest: true,
        })
    }

    /// Read-only view of the state machine — heartbeat inspects it to
    /// decide whether a 410 means Expired or GraceExhausted.
    pub(crate) fn state(&self) -> &SessionState {
        &self.state
    }

    /// Drop consumed nonces whose envelopes are expired anyway — they
    /// can't be accepted again, so remembering them is waste. Called
    /// on every envelope-accept path.
    pub(crate) fn evict_expired_nonces(&mut self, now: DateTime<Utc>) {
        self.consumed.evict_expired(now);
    }

    /// Successful heartbeat: install the refreshed lease, clear grace.
    pub(crate) fn on_heartbeat_ok(&mut self, lease: Lease) {
        self.state.on_heartbeat_ok(lease);
    }

    /// Transient failure: first one fixes the grace deadline, later
    /// ones leave it untouched.
    pub(crate) fn on_transient_failure(&mut self, now: DateTime<Utc>) {
        self.state.on_transient_failure(now);
    }

    /// Terminal rejection. Drops the session key first — a dead
    /// session must not retain the material that could mint MACs.
    pub(crate) fn kill(&mut self, reason: DeadReason) {
        self.session_key = None;
        self.state.kill(reason);
    }
}

/// Manual Debug: the session key is redacted unconditionally. The
/// session id is shown — the client needs it for log correlation and
/// it is useless without the key.
impl fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSession")
            .field("session_id", &self.session_id)
            .field("session_key", &"[redacted]")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> ClientSession {
        ClientSession::new(
            Uuid::nil(),
            [0xAB; 32],
            Lease {
                session_id: Uuid::nil(),
                granted_at: Utc::now(),
                expires_at: Utc::now() + Duration::seconds(300),
                grace_period: Duration::seconds(60),
            },
            [0x77; 32],
        )
    }

    #[test]
    fn debug_never_leaks_session_key() {
        let s = session();
        let dbg = format!("{s:?}");
        // The key bytes would render as "171" (0xAB) in a debug list —
        // assert the marker is present and the material is not.
        assert!(dbg.contains("[redacted]"));
        assert!(!dbg.contains("171"));
    }

    #[test]
    fn kill_drops_key_and_stays_dead() {
        let mut s = session();
        s.kill(DeadReason::Revoked);
        assert!(!s.is_alive());
        assert!(matches!(
            s.session_key(),
            Err(ClientError::MissingSessionKey)
        ));
        assert!(matches!(
            s.authorize(),
            Err(ClientError::Core(KeystoneError::Revoked))
        ));
    }

    #[test]
    fn heartbeat_due_at_eighty_percent() {
        let granted = Utc::now();
        let mut s = session();
        s.on_heartbeat_ok(Lease {
            session_id: Uuid::nil(),
            granted_at: granted,
            expires_at: granted + Duration::seconds(100),
            grace_period: Duration::seconds(60),
        });
        let due = s.next_heartbeat_due(granted).unwrap();
        assert_eq!(due, granted + Duration::seconds(80));
    }

    #[test]
    fn grace_exhausted_authorize_kills_and_drops_key() {
        let mut s = session();
        // Enter grace, then push the observed server clock past the
        // deadline — authorize must turn the verdict into a kill.
        s.on_transient_failure(Utc::now());
        s.observe_server_time(Utc::now() + Duration::seconds(120));
        assert!(matches!(s.authorize(), Err(ClientError::GraceExhausted)));
        assert!(!s.is_alive());
        assert!(matches!(
            s.session_key(),
            Err(ClientError::MissingSessionKey)
        ));
    }

    #[test]
    fn handoff_in_grace_clamps_lease_to_deadline() {
        let mut s = session();
        let failure_at = Utc::now();
        s.on_transient_failure(failure_at);
        let deadline = failure_at + Duration::seconds(60);

        let (blob, key) = s.make_handoff("app", Duration::seconds(60)).unwrap();
        let app = ClientSession::from_handoff(&key, &blob, "app", Utc::now()).unwrap();
        // The sealed lease dies with the grace window (~60s out), not
        // at the original 300s lease expiry.
        let SessionState::Active { lease } = app.state() else {
            panic!("handoff session must open Active")
        };
        assert!(lease.expires_at <= deadline + Duration::seconds(1));
        assert!(lease.expires_at < failure_at + Duration::seconds(300));
    }

    #[test]
    fn handoff_session_is_pending_until_attest() {
        let s = session();
        let (blob, key) = s.make_handoff("app", Duration::seconds(60)).unwrap();
        let mut app = ClientSession::from_handoff(&key, &blob, "app", Utc::now()).unwrap();
        assert!(matches!(
            app.authorize(),
            Err(ClientError::NotAuthenticated)
        ));
        app.clear_pending_attest();
        assert!(app.authorize().is_ok());
    }
}
