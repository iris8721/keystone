use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{KeystoneError, Result};

/// An authorization lease: access granted for a bounded window, renewed
/// by signed heartbeats. The lease is the only thing that keeps
/// protected operations alive — when it dies, they die.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub session_id: Uuid,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// How long the app may keep running on network failure. Fixed at
    /// first failure — retries never extend it.
    pub grace_period: Duration,
}

impl Lease {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// Client-side session state machine.
///
/// Active → Active        on successful heartbeat (lease refreshed)
/// Active → Grace         on transient failure (deadline fixed NOW)
/// Grace  → Active        on successful heartbeat (grace cleared)
/// Grace  → Dead          when now > grace_deadline
/// any    → Dead          on explicit rejection or revocation
///
/// The critical invariant: entering Grace sets an absolute deadline.
/// Subsequent failures while in Grace do NOT move it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionState {
    Active { lease: Lease },
    Grace { lease: Lease, deadline: DateTime<Utc> },
    Dead { reason: DeadReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadReason {
    Rejected,
    Revoked,
    Expired,
    GraceExhausted,
}

impl SessionState {
    /// Record a successful heartbeat: install the refreshed lease,
    /// clear any grace state. A Dead session stays dead — a heartbeat
    /// must never resurrect a rejected or revoked session.
    pub fn on_heartbeat_ok(&mut self, lease: Lease) {
        if matches!(self, SessionState::Dead { .. }) {
            return;
        }
        *self = SessionState::Active { lease };
    }

    /// Record a transient failure. First failure starts the grace clock;
    /// later failures leave the deadline untouched.
    pub fn on_transient_failure(&mut self, now: DateTime<Utc>) {
        if let SessionState::Active { lease } = self {
            *self = SessionState::Grace {
                deadline: now + lease.grace_period,
                lease: lease.clone(),
            };
        }
        // Already in Grace or Dead: deadline is fixed, do nothing.
    }

    /// Explicit rejection or revocation — immediate death, no grace.
    pub fn kill(&mut self, reason: DeadReason) {
        *self = SessionState::Dead { reason };
    }

    /// May protected operations run right now?
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
                DeadReason::Rejected | DeadReason::Revoked => KeystoneError::Revoked,
                DeadReason::Expired => KeystoneError::Expired,
                DeadReason::GraceExhausted => KeystoneError::GraceExhausted,
            }),
        }
    }
}
