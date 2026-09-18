//! Entitlement model — what an account is allowed to run.
//!
//! Authentication answers "who is this"; entitlement answers "what are
//! they allowed". The server checks both on every exchange: a valid
//! login with no grant for the requested product must still fail.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::KeystoneError;

/// A product grant attached to an account. Expiry is absolute — an
/// expired entitlement authorizes nothing even if the credentials that
/// fetched it are still valid, and sessions must not outlive it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub account: String,
    pub product: String,
    pub expires_at: DateTime<Utc>,
    /// Feature names the grant covers — the payload consumes these as
    /// per-feature grant tokens at runtime.
    pub features: Vec<String>,
}

/// Proof of authentication, deliberately minimal: who logged in.
/// Entitlements are fetched separately — an account with zero grants
/// still authenticates, then fails authorization on the product check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountIdentity {
    pub account: String,
}

/// Where entitlement records come from. The production source is forum
/// group sync (xenforo, per DESIGN.md); the server ships a stub for
/// development.
///
/// `Ok(None)` from either method means "no such record" — bad
/// credentials or no grant. `Err` is reserved for backend failures,
/// which fail closed but must be logged distinctly from ordinary
/// denials: a down backend is an outage, not an attack.
#[async_trait]
pub trait EntitlementSource: Send + Sync {
    /// Prove the account/secret pair. `None` on bad credentials — a
    /// failed login is not a backend error.
    async fn authenticate(
        &self,
        account: &str,
        secret: &str,
    ) -> Result<Option<AccountIdentity>, KeystoneError>;

    /// Fetch the account's grant for a specific product. `None` means
    /// the account exists but holds no grant for `product`.
    async fn entitlement(
        &self,
        account: &str,
        product: &str,
    ) -> Result<Option<Entitlement>, KeystoneError>;

    /// sha256 of the DER of the client certificate bound to this
    /// account, if any. When `Some`, the transport must have presented
    /// exactly that certificate — the account file's `cert_sha256`
    /// field pins the install, not just the CA. `None` means any
    /// CA-issued client cert authenticates the install.
    ///
    /// Default returns `None` so sources without cert binding (the dev
    /// stub, tests) compile unchanged.
    async fn cert_sha256(&self, _account: &str) -> Result<Option<[u8; 32]>, KeystoneError> {
        Ok(None)
    }
}
