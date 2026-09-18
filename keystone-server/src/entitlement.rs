//! Development entitlement source.
//!
//! This stub stands in for the real backend — the file-backed
//! `LocalAccounts` in `accounts.rs` — so the full exchange flow stays
//! exercisable without an accounts file. It only ever activates behind
//! KEYSTONE_DEV_SEED=1. The `EntitlementSource` trait is the seam:
//! backends slot in behind it without touching the routes.

use std::collections::HashMap;
use std::sync::Arc;

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use keystone_core::{
    AccountIdentity, Entitlement, EntitlementSource, KeystoneError,
};

/// In-memory account table: account → (argon2 secret hash, product grants).
///
/// Secrets are stored as argon2 hashes even in the stub — a dev stub
/// that keeps plaintext passwords teaches the wrong habit and would
/// leak them in any accidental dump.
pub struct StubEntitlementSource {
    accounts: HashMap<String, AccountEntry>,
    /// Constant argon2 hash verified for unknown accounts so a
    /// missing-account lookup costs the same as a wrong-password one —
    /// otherwise response timing leaks which accounts exist.
    dummy_hash: String,
}

struct AccountEntry {
    secret_hash: String,
    entitlements: Vec<Entitlement>,
}

impl StubEntitlementSource {
    /// Seed the table. `seeds` is `(account, plaintext secret,
    /// entitlements)` — plaintext only crosses this constructor and is
    /// hashed immediately.
    pub fn new(seeds: Vec<(String, String, Vec<Entitlement>)>) -> Self {
        let argon2 = Argon2::default();
        let hash = |secret: &str| {
            let salt = SaltString::generate(&mut OsRng);
            argon2
                .hash_password(secret.as_bytes(), &salt)
                .expect("argon2 hashing a dev seed must not fail")
                .to_string()
        };
        let dummy_hash = hash("keystone-timing-dummy");
        let accounts = seeds
            .into_iter()
            .map(|(account, secret, entitlements)| {
                (
                    account,
                    AccountEntry {
                        secret_hash: hash(&secret),
                        entitlements,
                    },
                )
            })
            .collect();
        Self {
            accounts,
            dummy_hash,
        }
    }
}

#[async_trait]
impl EntitlementSource for StubEntitlementSource {
    async fn authenticate(
        &self,
        account: &str,
        secret: &str,
    ) -> Result<Option<AccountIdentity>, KeystoneError> {
        // Unknown account → verify against the dummy hash anyway so the
        // argon2 cost is paid either way and timing stays uniform.
        let stored = self
            .accounts
            .get(account)
            .map(|e| e.secret_hash.as_str())
            .unwrap_or(&self.dummy_hash);
        let parsed = PasswordHash::new(stored)
            .map_err(|e| KeystoneError::Malformed(format!("stored hash corrupt: {e}")))?;
        let ok = Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .is_ok();
        if ok && self.accounts.contains_key(account) {
            Ok(Some(AccountIdentity {
                account: account.to_string(),
            }))
        } else {
            // Bad credentials are a denial, not a backend failure.
            Ok(None)
        }
    }

    async fn entitlement(
        &self,
        account: &str,
        product: &str,
    ) -> Result<Option<Entitlement>, KeystoneError> {
        Ok(self
            .accounts
            .get(account)
            .and_then(|e| e.entitlements.iter().find(|g| g.product == product).cloned()))
    }
}

/// Build the dev entitlement backend when KEYSTONE_DEV_SEED allows it.
///
/// Returns `None` when seeding is disabled — main() treats that as
/// fatal until a real backend exists, because a server that can
/// authenticate no one is a server that authorizes no one, and running
/// it anyway would only hide the misconfiguration.
pub fn dev_seed_source(dev_seed_enabled: bool) -> Option<Arc<dyn EntitlementSource>> {
    if !dev_seed_enabled {
        return None;
    }
    // Dev-only seed account. The real entitlement backend is forum
    // group sync (xenforo); until it lands, this one account keeps the
    // whole flow exercisable. Never a path to production credentials.
    Some(Arc::new(StubEntitlementSource::new(vec![
        (
            "dev".to_string(),
            "devpass".to_string(),
            vec![Entitlement {
                account: "dev".to_string(),
                product: "dev-product".to_string(),
                expires_at: Utc::now() + Duration::days(365),
                features: vec!["all".to_string()],
            }],
        ),
        // A zero-grant account: authenticates fine, then fails the
        // product check — exercises the authn/authz split.
        ("nogrant".to_string(), "nograntpass".to_string(), vec![]),
    ])))
}
