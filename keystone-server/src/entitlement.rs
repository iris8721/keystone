//! Development entitlement source, active only behind `KEYSTONE_DEV_SEED=1`
//! with `KEYSTONE_ALLOW_INSECURE=1`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use keystone_core::{AccountIdentity, BackendError, Entitlement, EntitlementSource};

use crate::accounts::{SecretVerifier, hash_secret};

/// In-memory accounts with argon2-hashed secrets and fixed grants.
pub struct StubEntitlementSource {
    accounts: HashMap<String, (String, Vec<Entitlement>)>,
    verifier: SecretVerifier,
}

impl StubEntitlementSource {
    /// Seed the table from `(account, plaintext secret, grants)`; secrets
    /// are hashed immediately.
    pub fn new(seeds: Vec<(String, String, Vec<Entitlement>)>) -> Self {
        let accounts = seeds
            .into_iter()
            .map(|(account, secret, grants)| (account, (hash_secret(&secret), grants)))
            .collect();
        Self {
            accounts,
            verifier: SecretVerifier::new(),
        }
    }
}

#[async_trait]
impl EntitlementSource for StubEntitlementSource {
    async fn authenticate(
        &self,
        account: &str,
        secret: &str,
    ) -> Result<Option<AccountIdentity>, BackendError> {
        let stored = self.accounts.get(account).map(|(hash, _)| hash.clone());
        Ok(self
            .verifier
            .verify(stored, secret)
            .await?
            .then(|| AccountIdentity {
                account: account.to_string(),
            }))
    }

    async fn entitlement(
        &self,
        account: &str,
        product: &str,
    ) -> Result<Option<Entitlement>, BackendError> {
        let now = Utc::now();
        Ok(self.accounts.get(account).and_then(|(_, grants)| {
            grants
                .iter()
                .find(|g| g.product == product && now < g.expires_at)
                .cloned()
        }))
    }
}

/// The dev backend: account `dev`/`devpass` with a year of `dev-product`
/// (feature `all`), and `nogrant`/`nograntpass` with no grants.
pub fn dev_seed_source() -> Arc<dyn EntitlementSource> {
    Arc::new(StubEntitlementSource::new(vec![
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
        ("nogrant".to_string(), "nograntpass".to_string(), vec![]),
    ]))
}
