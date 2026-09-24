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
}
