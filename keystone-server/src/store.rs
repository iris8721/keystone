//! In-memory session store.
//!
//! Sessions are the server's authority over live access: who holds a
//! lease, what state the session is in, which response nonces are
//! already spent. Losing them on restart is safe by design — clients
//! simply re-exchange, and nothing offline can resurrect a session.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use keystone_core::{ConsumedSet, DeadReason, SessionState};
use uuid::Uuid;

/// Everything the server knows about one live session. Not Clone on
/// purpose: the session key must not be casually copied — read paths
/// get a `SessionView` instead.
pub struct SessionRecord {
    pub session_id: Uuid,
    pub account: String,
    pub product: String,
    /// sha256 of the client-supplied HWID fingerprint. An anomaly
    /// signal, not identity (README: assume spoofable) — and never
    /// the raw fingerprint, so the store can't be mined for hardware
    /// IDs.
    pub hwid_hash: [u8; 32],
    /// Per-session symmetric key minted at exchange. Heartbeat and
    /// attest MACs prove possession of it; it never leaves the
    /// exchange response.
    pub session_key: [u8; 32],
    /// Sessions must not outlive the grant that created them —
    /// heartbeat kills the session once this passes.
    pub entitlement_expires_at: DateTime<Utc>,
    /// sha256 of the client certificate the exchange was performed
    /// with, recorded only when the account pins one. Every later
    /// MAC'd request on this session must arrive over the same cert —
    /// a lifted session key is useless without the install's identity.
    pub cert_sha256: Option<[u8; 32]>,
    pub state: SessionState,
    /// Heartbeat nonces already accepted for this session — replay
    /// rejection for client-generated nonces.
    pub consumed: ConsumedSet,
    pub created_at: DateTime<Utc>,
}

/// Manual Debug: the session key is the proof-of-possession secret for
/// every MAC'd route — it must never reach a log line.
impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecord")
            .field("session_id", &self.session_id)
            .field("account", &self.account)
            .field("product", &self.product)
            .field("hwid_hash", &self.hwid_hash)
            .field("session_key", &"[redacted]")
            .field("entitlement_expires_at", &self.entitlement_expires_at)
            .field(
                "cert_sha256",
                &self.cert_sha256.map_or("absent", |_| "present"),
            )
            .field("state", &self.state)
            .field("consumed", &self.consumed)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Sanitized snapshot for read paths — everything except the session
/// key and the consumed set, which no reader outside `with_mut` should
/// ever touch.
#[derive(Debug)]
pub struct SessionView {
    pub session_id: Uuid,
    pub account: String,
    pub product: String,
    pub hwid_hash: [u8; 32],
    pub entitlement_expires_at: DateTime<Utc>,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
}

/// (hwid_hash, last_seen) — factored out of the map type for clarity.
type FingerprintSighting = ([u8; 32], DateTime<Utc>);

/// `Arc`-shared so `AppState` clones cheaply; `RwLock` because reads
/// (attest lookups) vastly outnumber writes.
#[derive(Debug, Clone, Default)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<Uuid, SessionRecord>>>,
    /// account → (hwid_hash, last_seen). The anomaly signal from
    /// README: same account presenting a materially different
    /// fingerprint inside a short window is worth flagging — never a
    /// hard gate, because facade exists and HWID is spoofable.
    fingerprints: Arc<RwLock<HashMap<String, FingerprintSighting>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, record: SessionRecord) {
        self.sessions
            .write()
            .expect("session store poisoned")
            .insert(record.session_id, record);
    }

    /// Sanitized snapshot of a session. For check-then-update flows use
    /// `with_mut` instead — a read followed by a separate write opens a
    /// race between concurrent requests on the same session.
    pub fn get(&self, session_id: &Uuid) -> Option<SessionView> {
        self.sessions
            .read()
            .expect("session store poisoned")
            .get(session_id)
            .map(|rec| SessionView {
                session_id: rec.session_id,
                account: rec.account.clone(),
                product: rec.product.clone(),
                hwid_hash: rec.hwid_hash,
                entitlement_expires_at: rec.entitlement_expires_at,
                state: rec.state.clone(),
                created_at: rec.created_at,
            })
    }

    /// Atomic check-and-mutate under one write lock. The closure
    /// returns the handler's result so state inspection and update
    /// can't be interleaved by another request.
    pub fn with_mut<R>(
        &self,
        session_id: &Uuid,
        f: impl FnOnce(&mut SessionRecord) -> R,
    ) -> Option<R> {
        self.sessions
            .write()
            .expect("session store poisoned")
            .get_mut(session_id)
            .map(f)
    }

    /// Explicit revocation — immediate death, no grace.
    pub fn revoke(&self, session_id: &Uuid) -> bool {
        self.with_mut(session_id, |rec| rec.state.kill(DeadReason::Revoked))
            .is_some()
    }

    /// Kill every live session belonging to `account` — the
    /// operator-facing "pull this user" form of revocation. Returns
    /// how many sessions were killed; already-dead records keep their
    /// original reason.
    pub fn revoke_account(&self, account: &str) -> usize {
        let mut killed = 0;
        for rec in self
            .sessions
            .write()
            .expect("session store poisoned")
            .values_mut()
        {
            if rec.account == account && !matches!(rec.state, SessionState::Dead { .. }) {
                rec.state.kill(DeadReason::Revoked);
                killed += 1;
            }
        }
        killed
    }

    /// Kill every live session, whatever the account — the response to
    /// a compromised issuer key (README: revoke the key AND
    /// invalidate affected sessions). Returns how many were killed;
    /// already-dead records keep their original reason.
    pub fn revoke_all(&self, reason: DeadReason) -> usize {
        let mut killed = 0;
        for rec in self
            .sessions
            .write()
            .expect("session store poisoned")
            .values_mut()
        {
            if !matches!(rec.state, SessionState::Dead { .. }) {
                rec.state.kill(reason);
                killed += 1;
            }
        }
        killed
    }

    /// Reclaim records that can never matter again: sessions whose
    /// lease plus grace window has fully passed. Dead records are kept
    /// until then — dropping them early would turn "revoked" into
    /// "unknown" and lose the 403-vs-404 distinction.
    pub fn sweep(&self, now: DateTime<Utc>) {
        self.sessions
            .write()
            .expect("session store poisoned")
            .retain(|_, rec| match &rec.state {
                SessionState::Active { lease } => now <= lease.expires_at + lease.grace_period,
                // The server is authoritative: it only ever creates
                // Active or Dead — Grace is client-side bookkeeping.
                // A Grace record here means the store was seeded from
                // outside; retain it like Dead so it can't linger
                // past the grant that created it.
                SessionState::Grace { .. } | SessionState::Dead { .. } => {
                    now <= rec.entitlement_expires_at
                }
            });
    }

    /// Record a fingerprint sighting for an account. Returns true when
    /// the account was seen inside `window` with a DIFFERENT hash —
    /// the anomaly case. First sightings and same-hash re-sightings
    /// return false. The record updates either way.
    pub fn check_fingerprint(
        &self,
        account: &str,
        hwid_hash: [u8; 32],
        now: DateTime<Utc>,
        window: chrono::Duration,
    ) -> bool {
        let mut fps = self
            .fingerprints
            .write()
            .expect("fingerprint cache poisoned");
        let anomalous = match fps.get(account) {
            Some((prev, seen)) => *prev != hwid_hash && now - *seen < window,
            None => false,
        };
        fps.insert(account.to_string(), (hwid_hash, now));
        anomalous
    }
}
