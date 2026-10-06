//! Entitlement model — what an account is allowed to run.
//!
//! Authentication answers "who is this"; entitlement answers "what are
//! they allowed". The server checks both on every exchange: a valid
//! login with no grant for the requested product must still fail.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::BackendError;

/// A product grant attached to an account. Expiry is absolute — an
/// expired entitlement authorizes nothing even if the credentials that
/// fetched it are still valid, and sessions must not outlive it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    /// Account holding the grant.
    pub account: String,
    /// Product granted.
    pub product: String,
    /// First instant at which the grant is dead.
    pub expires_at: DateTime<Utc>,
    /// Feature names the grant covers.
    pub features: Vec<String>,
}

/// Proof of authentication, deliberately minimal: who logged in.
/// Entitlements are fetched separately — an account with zero grants
/// still authenticates, then fails authorization on the product check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountIdentity {
    /// The authenticated account name.
    pub account: String,
}

/// Where accounts and grants come from. `Ok(None)` means no such record
/// (bad credentials or no grant); `Err` is a backend outage, which callers
/// fail closed on and report distinctly from a denial.
#[async_trait]
pub trait EntitlementSource: Send + Sync {
    /// Prove the account/secret pair; `None` on bad credentials.
    async fn authenticate(
        &self,
        account: &str,
        secret: &str,
    ) -> Result<Option<AccountIdentity>, BackendError>;

    /// The account's grant for `product`; `None` when it holds none.
    async fn entitlement(
        &self,
        account: &str,
        product: &str,
    ) -> Result<Option<Entitlement>, BackendError>;

    /// sha256 of the client certificate DER the account is pinned to, if
    /// any. Defaults to `None` (no pin).
    async fn cert_sha256(&self, _account: &str) -> Result<Option<[u8; 32]>, BackendError> {
        Ok(None)
    }

    /// Bind the account to `hwid_hash` when it has no machine lock yet and
    /// return the lock now in force; `None` when this backend does not bind
    /// machines (the default) or the account is unknown. A returned lock
    /// that differs from `hwid_hash` is a rejection. The check-and-set must
    /// be atomic so concurrent first exchanges cannot bind two machines.
    async fn bind_hwid(
        &self,
        _account: &str,
        _hwid_hash: [u8; 32],
    ) -> Result<Option<[u8; 32]>, BackendError> {
        Ok(None)
    }

    /// Clear the account's machine lock. `None` for an unknown account,
    /// otherwise whether a lock was held. Defaults to `None` (backend does
    /// not bind machines).
    async fn clear_hwid_lock(&self, _account: &str) -> Result<Option<bool>, BackendError> {
        Ok(None)
    }

    /// Operator view of the account; `None` when there is no such account.
    async fn account_summary(
        &self,
        _account: &str,
    ) -> Result<Option<AccountSummary>, BackendError> {
        Ok(None)
    }
}

/// One grant as the operator account view reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSummary {
    /// Product granted.
    pub product: String,
    /// First instant at which the grant is dead.
    pub expires_at: DateTime<Utc>,
}

/// What an operator may see of an account: no credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummary {
    /// Whether the account is bound to a machine fingerprint.
    pub hwid_locked: bool,
    /// Every grant, expired or not.
    pub grants: Vec<GrantSummary>,
}
