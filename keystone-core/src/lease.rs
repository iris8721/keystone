//! Leases and the client-side session state machine.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{KeystoneError, Result};

/// Access granted for a bounded window and renewed by signed heartbeats.
/// When the lease dies, every protected operation dies with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    /// The session the lease belongs to.
    pub session_id: Uuid,
    /// When the server granted this lease.
    #[serde(with = "crate::wire::millis")]
    pub granted_at: DateTime<Utc>,
    /// First instant at which the lease no longer authorizes anything.
    #[serde(with = "crate::wire::millis")]
    pub expires_at: DateTime<Utc>,
    /// How long protected operations may continue after the first
    /// transient failure; the deadline is fixed when grace starts.
    #[serde(with = "crate::wire::duration_millis")]
    pub grace_period: Duration,
}

impl Lease {
    /// True at and after `expires_at`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// Client-side session state machine.
///
/// Active and Grace move to Active on a successful heartbeat, Active
/// moves to Grace on the first transient failure, and anything moves to
/// Dead on a verdict or an exhausted grace deadline. Dead is terminal,
/// and entering Grace fixes a deadline that later failures never move.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionState {
    /// Heartbeats are succeeding.
    Active {
        /// The current lease.
        lease: Lease,
    },
    /// A transient failure started the grace clock.
    Grace {
        /// The last lease the server granted.
        lease: Lease,
        /// Absolute instant after which the session is dead.
        #[serde(with = "crate::wire::millis")]
        deadline: DateTime<Utc>,
    },
    /// The session is over for good.
    Dead {
        /// Why it ended.
        reason: DeadReason,
    },
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadReason {
    /// The server rejected the session's proof.
    Rejected,
    /// The session, its account, or its grant was revoked.
    Revoked,
    /// The server no longer knows the session.
    UnknownSession,
    /// The lease or grant expired.
    Expired,
    /// Grace ran out before a heartbeat succeeded.
    GraceExhausted,
}

impl SessionState {
    /// Install a refreshed lease and clear grace. Dead stays dead, and a
    /// Grace session whose deadline already passed dies instead of being
    /// resurrected by a late response.
    pub fn on_heartbeat_ok(&mut self, lease: Lease, now: DateTime<Utc>) {
        match self {
            SessionState::Dead { .. } => {}
            SessionState::Grace { deadline, .. } if now > *deadline => {
                *self = SessionState::Dead {
                    reason: DeadReason::GraceExhausted,
                };
            }
            _ => *self = SessionState::Active { lease },
        }
    }

    /// Record a transient failure. Only the first failure starts the
    /// grace clock; later ones leave the deadline where it is.
    pub fn on_transient_failure(&mut self, now: DateTime<Utc>) {
        if let SessionState::Active { lease } = self {
            *self = SessionState::Grace {
                deadline: now + lease.grace_period,
                lease: lease.clone(),
            };
        }
    }

    /// Immediate death with no grace.
    pub fn kill(&mut self, reason: DeadReason) {
        *self = SessionState::Dead { reason };
    }

    /// Whether protected operations may run at `now`. Errors name the
    /// reason: `Expired`, `GraceExhausted`, or the dead state's reason.
    pub fn authorize(&self, now: DateTime<Utc>) -> Result<()> {
        match self {
            SessionState::Active { lease } => {
                if lease.is_expired(now) {
                    Err(KeystoneError::Expired)
                } else {
                    Ok(())
                }
            }
            SessionState::Grace { lease, deadline } => {
                if now > *deadline {
                    Err(KeystoneError::GraceExhausted)
                } else if lease.is_expired(now) {
                    Err(KeystoneError::Expired)
                } else {
                    Ok(())
                }
            }
            SessionState::Dead { reason } => Err(match reason {
                DeadReason::Rejected => KeystoneError::Rejected,
                DeadReason::Revoked => KeystoneError::Revoked,
                DeadReason::UnknownSession => KeystoneError::UnknownSession,
                DeadReason::Expired => KeystoneError::Expired,
                DeadReason::GraceExhausted => KeystoneError::GraceExhausted,
            }),
        }
    }
}
