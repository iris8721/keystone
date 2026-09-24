//! The local accounts file: the schema keystone-server reads and xtask
//! writes.
//!
//! ```json
//! {"accounts":[{"name":"dev","secret_hash":"<argon2 PHC>",
//!   "entitlements":[{"product":"x","expires_at":"<rfc3339>",
//!   "features":["a","b"]}],"cert_sha256":"<optional hex>"}]}
//! ```

use std::fmt;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::KeystoneError;

/// The parsed contents of the accounts file.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AccountFile {
    /// Every account, in file order.
    pub accounts: Vec<AccountRecord>,
}

/// One account: credentials, product grants, optional cert binding.
#[derive(Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    /// Account name; also the required client certificate CN.
    pub name: String,
    /// Argon2 PHC string, never the plaintext secret.
    pub secret_hash: String,
    /// Product grants.
    #[serde(default)]
    pub entitlements: Vec<AccountGrant>,
    /// Hex sha256 of the client certificate DER this account is pinned
    /// to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_sha256: Option<String>,
}

/// A product grant as stored in the file; the account is the record
/// holding it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountGrant {
    /// Product name.
    pub product: String,
    /// First instant at which the grant is dead.
    pub expires_at: DateTime<Utc>,
    /// Feature names the grant covers.
    #[serde(default)]
    pub features: Vec<String>,
}

impl AccountFile {
    /// Read and parse the accounts file. Read failures are `Io`; invalid
    /// JSON is `Malformed`.
    pub fn load(path: &Path) -> Result<Self, KeystoneError> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text)
            .map_err(|e| KeystoneError::Malformed(format!("accounts file {}: {e}", path.display())))
    }

    /// Atomically replace the accounts file with an owner-only copy via
    /// [`crate::fs::write_owner_only_atomic`]. Write failures are `Io`.
    pub fn save(&self, path: &Path) -> Result<(), KeystoneError> {
        let text =
            zeroize::Zeroizing::new(serde_json::to_string_pretty(self).map_err(|e| {
                KeystoneError::Malformed(format!("serializing accounts file: {e}"))
            })?);
        crate::fs::write_owner_only_atomic(path, text.as_bytes())?;
        Ok(())
    }
}

/// Redacts `secret_hash`.
impl fmt::Debug for AccountRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountRecord")
            .field("name", &self.name)
            .field("secret_hash", &"[redacted]")
            .field("entitlements", &self.entitlements)
            .field("cert_sha256", &self.cert_sha256)
            .finish_non_exhaustive()
    }
}

/// Delegates to the redacting record Debug.
impl fmt::Debug for AccountFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountFile")
            .field("accounts", &self.accounts)
            .finish_non_exhaustive()
    }
}
