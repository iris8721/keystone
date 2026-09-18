//! The verifier's trust root: which issuer keys it accepts, by id.
//!
//! README §Key rotation — "the old key stays trusted until
//! revoked" — needs the verifier to hold more than one pinned key and
//! to be able to stop trusting one of them without a rebuild. A
//! `TrustedIssuers` is baked into a build with every key the server may
//! sign under; revocations arrive later, inside signed responses from a
//! still-trusted key, and take effect immediately.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::VerifyingKey;

use crate::error::{KeystoneError, Result};

/// Issuer verifying keys keyed by `key_id`, plus the ids that have been
/// revoked. A revoked id stays in the map so a re-insert cannot quietly
/// resurrect it — revocation is a one-way transition.
#[derive(Clone)]
pub struct TrustedIssuers {
    keys: BTreeMap<u8, VerifyingKey>,
    revoked: BTreeSet<u8>,
}

impl TrustedIssuers {
    /// A trust root with exactly one key — the common case for a build
    /// that has never been through a rotation.
    pub fn single(key_id: u8, key: VerifyingKey) -> Self {
        Self::new([(key_id, key)])
    }

    pub fn new(keys: impl IntoIterator<Item = (u8, VerifyingKey)>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
            revoked: BTreeSet::new(),
        }
    }

    /// Add or replace the key under `key_id`. Does not clear a prior
    /// revocation of that id — a compromised id is dead for good.
    pub fn insert(&mut self, key_id: u8, key: VerifyingKey) {
        self.keys.insert(key_id, key);
    }

    /// Stop trusting `key_id`. Idempotent; revoking an id that was
    /// never inserted is recorded too, so a key later distributed under
    /// that id is refused.
    pub fn revoke(&mut self, key_id: u8) {
        self.revoked.insert(key_id);
    }

    pub fn is_revoked(&self, key_id: u8) -> bool {
        self.revoked.contains(&key_id)
    }

    /// The key to verify a value signed under `key_id`. Unknown and
    /// revoked ids fail the same way — a verifier must not reveal which
    /// keys it once trusted.
    pub fn key_for(&self, key_id: u8) -> Result<&VerifyingKey> {
        if self.revoked.contains(&key_id) {
            return Err(KeystoneError::UntrustedIssuer { key_id });
        }
        self.keys
            .get(&key_id)
            .ok_or(KeystoneError::UntrustedIssuer { key_id })
    }

    /// Every id with a key, revoked or not, ascending.
    pub fn key_ids(&self) -> Vec<u8> {
        self.keys.keys().copied().collect()
    }

    pub fn revoked_ids(&self) -> Vec<u8> {
        self.revoked.iter().copied().collect()
    }
}

/// Manual Debug: ids only. The keys are public, but a log line listing
/// 32-byte keys per session is noise, not signal.
impl fmt::Debug for TrustedIssuers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedIssuers")
            .field("key_ids", &self.key_ids())
            .field("revoked", &self.revoked_ids())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Issuer;

    #[test]
    fn key_for_resolves_by_id() {
        let a = Issuer::generate_with_id(1);
        let b = Issuer::generate_with_id(2);
        let trusted = TrustedIssuers::new([(1, a.verifying_key()), (2, b.verifying_key())]);
        assert_eq!(trusted.key_for(1).unwrap(), &a.verifying_key());
        assert_eq!(trusted.key_for(2).unwrap(), &b.verifying_key());
        assert!(matches!(
            trusted.key_for(3),
            Err(KeystoneError::UntrustedIssuer { key_id: 3 })
        ));
    }

    #[test]
    fn revoke_is_one_way() {
        let a = Issuer::generate_with_id(1);
        let mut trusted = TrustedIssuers::single(1, a.verifying_key());
        trusted.revoke(1);
        assert!(trusted.is_revoked(1));
        assert!(matches!(
            trusted.key_for(1),
            Err(KeystoneError::UntrustedIssuer { key_id: 1 })
        ));
        // Re-inserting the same id must not resurrect it.
        trusted.insert(1, a.verifying_key());
        assert!(trusted.key_for(1).is_err());
        assert_eq!(trusted.key_ids(), vec![1]);
        assert_eq!(trusted.revoked_ids(), vec![1]);
    }

    #[test]
    fn revoking_unknown_id_is_remembered() {
        let mut trusted = TrustedIssuers::new([]);
        trusted.revoke(9);
        trusted.insert(9, Issuer::generate_with_id(9).verifying_key());
        assert!(matches!(
            trusted.key_for(9),
            Err(KeystoneError::UntrustedIssuer { key_id: 9 })
        ));
    }

    #[test]
    fn debug_prints_ids_not_keys() {
        let a = Issuer::generate_with_id(4);
        let mut trusted = TrustedIssuers::single(4, a.verifying_key());
        trusted.revoke(2);
        let out = format!("{trusted:?}");
        assert_eq!(out, "TrustedIssuers { key_ids: [4], revoked: [2] }");
    }
}
