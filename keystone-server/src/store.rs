//! Session, nonce, and handoff storage.
//!
//! Routes read a record with its version, validate, and write back with
//! compare-and-swap, so concurrent requests on one session never lose an
//! update. Nonce consumption and handoff redemption are atomic
//! insert-if-absent / take operations with exactly one winner.

use std::collections::HashMap;
use std::fmt;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use keystone_core::{BackendError, ConsumedSet, DeadReason, Lease};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Everything the server knows about one session. Serializable for durable
/// stores; `Debug` redacts the key.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionRecord {
    /// The session.
    pub session_id: Uuid,
    /// Account that owns the session.
    pub account: String,
    /// Product the session is for; payload routes serve nothing else.
    pub product: String,
    /// Loader session this child was attested from; `None` for exchanged sessions.
    pub parent: Option<Uuid>,
    /// sha256 of the exchange HWID fingerprint.
    pub hwid_hash: [u8; 32],
    /// Key for the session's request MACs.
    pub session_key: Zeroizing<[u8; 32]>,
    /// sha256 of the client certificate the session was created over;
    /// every later request must present the same certificate.
    pub cert_sha256: Option<[u8; 32]>,
    /// Expiry of the grant as last resolved.
    pub grant_expires_at: DateTime<Utc>,
    /// The most recent lease granted.
    pub lease: Lease,
    /// Set once the session is over; dead records are kept until the last
    /// lease plus grace has passed.
    pub dead: Option<DeadReason>,
}

impl SessionRecord {
    /// The instant after which no client can still hold this session alive.
    pub fn retain_until(&self) -> DateTime<Utc> {
        self.lease.expires_at + self.lease.grace_period
    }
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRecord")
            .field("session_id", &self.session_id)
            .field("account", &self.account)
            .field("product", &self.product)
            .field("parent", &self.parent)
            .field("session_key", &"[redacted]")
            .field(
                "cert_sha256",
                &self.cert_sha256.map_or("absent", |_| "present"),
            )
            .field("grant_expires_at", &self.grant_expires_at)
            .field("lease", &self.lease)
            .field("dead", &self.dead)
            .finish_non_exhaustive()
    }
}

/// An outstanding single-use handoff. Serializable for durable stores;
/// `Debug` redacts the secret.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HandoffRecord {
    /// Identifies the handoff at attest time.
    pub handoff_id: [u8; 32],
    /// Keys the attest MAC and the child session key wrap.
    pub secret: Zeroizing<[u8; 32]>,
    /// The session that minted it.
    pub parent: Uuid,
    /// Identity the child must attest under.
    pub process_id: String,
    /// Account of the parent.
    pub account: String,
    /// Product of the parent.
    pub product: String,
    /// Last instant the handoff can be redeemed (exclusive).
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for HandoffRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandoffRecord")
            .field("handoff_id", &hex::encode(self.handoff_id))
            .field("secret", &"[redacted]")
            .field("parent", &self.parent)
            .field("process_id", &self.process_id)
            .field("product", &self.product)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Session storage seam. Implementations must make `replace`,
/// `consume_nonce`, `insert_handoff`, `take_handoff`, and
/// `bump_account_epoch` atomic.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Store a new record at version 0.
    async fn insert(&self, record: SessionRecord) -> Result<(), BackendError>;

    /// The record and its current version.
    async fn get(&self, id: &Uuid) -> Result<Option<(SessionRecord, u64)>, BackendError>;

    /// Write `record` only if the stored version is still `expected_version`;
    /// false when another writer got there first or the record is gone.
    async fn replace(
        &self,
        id: &Uuid,
        expected_version: u64,
        record: SessionRecord,
    ) -> Result<bool, BackendError>;

    /// Every session of `account`.
    async fn ids_for_account(&self, account: &str) -> Result<Vec<Uuid>, BackendError>;

    /// Direct children of `parent`.
    async fn children_of(&self, parent: &Uuid) -> Result<Vec<Uuid>, BackendError>;

    /// Every stored session.
    async fn all_ids(&self) -> Result<Vec<Uuid>, BackendError>;

    /// Record `nonce` for `session_id` until `expires_at`; true for exactly
    /// one caller per nonce, false for replays, stale values, or an unknown
    /// session.
    async fn consume_nonce(
        &self,
        session_id: &Uuid,
        nonce: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<bool, BackendError>;

    /// Store a handoff unless its parent already has `max_per_parent`
    /// unexpired handoffs outstanding; false when over the limit.
    async fn insert_handoff(
        &self,
        record: HandoffRecord,
        max_per_parent: usize,
    ) -> Result<bool, BackendError>;

    /// Remove and return a handoff; exactly one caller gets it.
    async fn take_handoff(
        &self,
        handoff_id: &[u8; 32],
    ) -> Result<Option<HandoffRecord>, BackendError>;

    /// How many times `account` has been revoked; 0 for accounts never revoked.
    async fn account_epoch(&self, account: &str) -> Result<u64, BackendError>;

    /// Increment the revocation epoch of `account`.
    async fn bump_account_epoch(&self, account: &str) -> Result<(), BackendError>;

    /// Drop sessions past [`SessionRecord::retain_until`], expired handoffs,
    /// and expired nonces; returns the number of sessions dropped.
    async fn sweep(&self, now: DateTime<Utc>) -> Result<usize, BackendError>;
}

struct Slot {
    record: SessionRecord,
    version: u64,
    nonces: ConsumedSet,
}

#[derive(Default)]
struct Tables {
    sessions: HashMap<Uuid, Slot>,
    handoffs: HashMap<[u8; 32], HandoffRecord>,
    epochs: HashMap<String, u64>,
}

/// In-process [`SessionStore`]. Everything is lost on restart, which is
/// safe: clients see `unknown_session` and re-exchange.
#[derive(Default)]
pub struct MemoryStore {
    tables: Mutex<Tables>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> parking_lot::MutexGuard<'_, Tables> {
        self.tables.lock()
    }
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tables = self.lock();
        f.debug_struct("MemoryStore")
            .field("sessions", &tables.sessions.len())
            .field("handoffs", &tables.handoffs.len())
            .finish()
    }
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn insert(&self, record: SessionRecord) -> Result<(), BackendError> {
        self.lock().sessions.insert(
            record.session_id,
            Slot {
                record,
                version: 0,
                nonces: ConsumedSet::new(),
            },
        );
        Ok(())
    }

    async fn get(&self, id: &Uuid) -> Result<Option<(SessionRecord, u64)>, BackendError> {
        Ok(self
            .lock()
            .sessions
            .get(id)
            .map(|slot| (slot.record.clone(), slot.version)))
    }

    async fn replace(
        &self,
        id: &Uuid,
        expected_version: u64,
        record: SessionRecord,
    ) -> Result<bool, BackendError> {
        let mut tables = self.lock();
        match tables.sessions.get_mut(id) {
            Some(slot) if slot.version == expected_version => {
                slot.record = record;
                slot.version += 1;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn ids_for_account(&self, account: &str) -> Result<Vec<Uuid>, BackendError> {
        Ok(self
            .lock()
            .sessions
            .values()
            .filter(|slot| slot.record.account == account)
            .map(|slot| slot.record.session_id)
            .collect())
    }

    async fn children_of(&self, parent: &Uuid) -> Result<Vec<Uuid>, BackendError> {
        Ok(self
            .lock()
            .sessions
            .values()
            .filter(|slot| slot.record.parent.as_ref() == Some(parent))
            .map(|slot| slot.record.session_id)
            .collect())
    }

    async fn all_ids(&self) -> Result<Vec<Uuid>, BackendError> {
        Ok(self.lock().sessions.keys().copied().collect())
    }

    async fn consume_nonce(
        &self,
        session_id: &Uuid,
        nonce: [u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<bool, BackendError> {
        let mut tables = self.lock();
        let Some(slot) = tables.sessions.get_mut(session_id) else {
            return Ok(false);
        };
        Ok(slot.nonces.consume(nonce, expires_at, Utc::now()).is_ok())
    }

    async fn insert_handoff(
        &self,
        record: HandoffRecord,
        max_per_parent: usize,
    ) -> Result<bool, BackendError> {
        let now = Utc::now();
        let mut tables = self.lock();
        let outstanding = tables
            .handoffs
            .values()
            .filter(|h| h.parent == record.parent && h.expires_at > now)
            .count();
        if outstanding >= max_per_parent {
            return Ok(false);
        }
        tables.handoffs.insert(record.handoff_id, record);
        Ok(true)
    }

    async fn take_handoff(
        &self,
        handoff_id: &[u8; 32],
    ) -> Result<Option<HandoffRecord>, BackendError> {
        Ok(self.lock().handoffs.remove(handoff_id))
    }

    async fn account_epoch(&self, account: &str) -> Result<u64, BackendError> {
        Ok(self.lock().epochs.get(account).copied().unwrap_or(0))
    }

    async fn bump_account_epoch(&self, account: &str) -> Result<(), BackendError> {
        *self.lock().epochs.entry(account.to_string()).or_insert(0) += 1;
        Ok(())
    }

    async fn sweep(&self, now: DateTime<Utc>) -> Result<usize, BackendError> {
        let mut tables = self.lock();
        let before = tables.sessions.len();
        tables
            .sessions
            .retain(|_, slot| now <= slot.record.retain_until());
        for slot in tables.sessions.values_mut() {
            slot.nonces.evict_expired(now);
        }
        tables.handoffs.retain(|_, h| h.expires_at > now);
        Ok(before - tables.sessions.len())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Duration;

    use super::*;

    fn record(lease_expires_at: DateTime<Utc>, grace: Duration) -> SessionRecord {
        let session_id = Uuid::new_v4();
        SessionRecord {
            session_id,
            account: "dev".into(),
            product: "dev-product".into(),
            parent: None,
            hwid_hash: [0u8; 32],
            session_key: Zeroizing::new([0xAB; 32]),
            cert_sha256: Some([0xCD; 32]),
            grant_expires_at: Utc::now() + Duration::days(30),
            lease: Lease {
                session_id,
                granted_at: Utc::now(),
                expires_at: lease_expires_at,
                grace_period: grace,
            },
            dead: None,
        }
    }

    fn handoff(parent: Uuid, expires_at: DateTime<Utc>) -> HandoffRecord {
        let mut id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
        HandoffRecord {
            handoff_id: id,
            secret: Zeroizing::new([7u8; 32]),
            parent,
            process_id: "app.exe".into(),
            account: "dev".into(),
            product: "dev-product".into(),
            expires_at,
        }
    }

    #[tokio::test]
    async fn replace_is_compare_and_swap() {
        let store = MemoryStore::new();
        let rec = record(Utc::now() + Duration::minutes(5), Duration::seconds(60));
        let id = rec.session_id;
        store.insert(rec).await.unwrap();
        let (mut first, version) = store.get(&id).await.unwrap().unwrap();
        let (mut second, same_version) = store.get(&id).await.unwrap().unwrap();
        assert_eq!(version, same_version);

        first.dead = Some(DeadReason::Revoked);
        assert!(store.replace(&id, version, first).await.unwrap());
        second.account = "stale writer".into();
        assert!(!store.replace(&id, version, second).await.unwrap());
        let (stored, newer) = store.get(&id).await.unwrap().unwrap();
        assert_eq!(stored.dead, Some(DeadReason::Revoked));
        assert_eq!(stored.account, "dev");
        assert_ne!(newer, version);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_nonce_is_consumed_by_exactly_one_caller() {
        let store = Arc::new(MemoryStore::new());
        let rec = record(Utc::now() + Duration::minutes(5), Duration::seconds(60));
        let id = rec.session_id;
        store.insert(rec).await.unwrap();
        let expires = Utc::now() + Duration::minutes(5);
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(
                    async move { store.consume_nonce(&id, [5u8; 32], expires).await.unwrap() },
                )
            })
            .collect();
        let mut winners = 0;
        for task in tasks {
            winners += usize::from(task.await.unwrap());
        }
        assert_eq!(winners, 1);
        assert!(
            !store
                .consume_nonce(&id, [6u8; 32], Utc::now())
                .await
                .unwrap()
        );
        assert!(
            !store
                .consume_nonce(&Uuid::new_v4(), [6u8; 32], expires)
                .await
                .unwrap()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_handoff_is_taken_by_exactly_one_caller() {
        let store = Arc::new(MemoryStore::new());
        let h = handoff(Uuid::new_v4(), Utc::now() + Duration::minutes(1));
        let id = h.handoff_id;
        assert!(store.insert_handoff(h, 4).await.unwrap());
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(async move { store.take_handoff(&id).await.unwrap().is_some() })
            })
            .collect();
        let mut winners = 0;
        for task in tasks {
            winners += usize::from(task.await.unwrap());
        }
        assert_eq!(winners, 1);
    }

    #[tokio::test]
    async fn outstanding_handoffs_are_capped_per_parent() {
        let store = MemoryStore::new();
        let parent = Uuid::new_v4();
        let live = Utc::now() + Duration::minutes(1);
        for _ in 0..2 {
            assert!(
                store
                    .insert_handoff(handoff(parent, live), 2)
                    .await
                    .unwrap()
            );
        }
        assert!(
            !store
                .insert_handoff(handoff(parent, live), 2)
                .await
                .unwrap()
        );
        assert!(
            store
                .insert_handoff(handoff(Uuid::new_v4(), live), 2)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn sweep_keeps_records_until_lease_plus_grace() {
        let store = MemoryStore::new();
        let now = Utc::now();
        let mut dead_in_grace = record(now - Duration::seconds(10), Duration::seconds(60));
        dead_in_grace.dead = Some(DeadReason::Revoked);
        let mut dead_past_grace = record(now - Duration::seconds(90), Duration::seconds(60));
        dead_past_grace.dead = Some(DeadReason::Revoked);
        let live_past_grace = record(now - Duration::seconds(90), Duration::seconds(60));
        let live = record(now + Duration::minutes(5), Duration::seconds(60));
        let kept = [dead_in_grace.session_id, live.session_id];
        let dropped = [dead_past_grace.session_id, live_past_grace.session_id];
        for rec in [dead_in_grace, dead_past_grace, live_past_grace, live] {
            store.insert(rec).await.unwrap();
        }
        let expired_handoff = handoff(Uuid::new_v4(), now - Duration::seconds(1));
        let expired_id = expired_handoff.handoff_id;
        store.insert_handoff(expired_handoff, 4).await.unwrap();

        assert_eq!(store.sweep(now).await.unwrap(), 2);
        for id in kept {
            assert!(store.get(&id).await.unwrap().is_some());
        }
        for id in dropped {
            assert!(store.get(&id).await.unwrap().is_none());
        }
        assert!(store.take_handoff(&expired_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn children_and_accounts_are_indexed() {
        let store = MemoryStore::new();
        let parent = record(Utc::now() + Duration::minutes(5), Duration::zero());
        let mut child = record(Utc::now() + Duration::minutes(5), Duration::zero());
        child.parent = Some(parent.session_id);
        let mut stranger = record(Utc::now() + Duration::minutes(5), Duration::zero());
        stranger.account = "someone-else".into();
        let (p, c) = (parent.session_id, child.session_id);
        for rec in [parent, child, stranger] {
            store.insert(rec).await.unwrap();
        }
        assert_eq!(store.children_of(&p).await.unwrap(), vec![c]);
        let mut dev = store.ids_for_account("dev").await.unwrap();
        dev.sort();
        let mut expected = vec![p, c];
        expected.sort();
        assert_eq!(dev, expected);
        assert_eq!(store.all_ids().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn account_epochs_count_bumps_per_account() {
        let store = MemoryStore::new();
        assert_eq!(store.account_epoch("dev").await.unwrap(), 0);
        store.bump_account_epoch("dev").await.unwrap();
        store.bump_account_epoch("dev").await.unwrap();
        assert_eq!(store.account_epoch("dev").await.unwrap(), 2);
        assert_eq!(store.account_epoch("other").await.unwrap(), 0);
    }

    #[test]
    fn records_round_trip_through_json() {
        let rec = record(Utc::now(), Duration::seconds(60));
        let back: SessionRecord =
            serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
        assert_eq!(back.session_id, rec.session_id);
        assert_eq!(*back.session_key, *rec.session_key);
        assert_eq!(
            back.lease.expires_at.timestamp_millis(),
            rec.lease.expires_at.timestamp_millis()
        );
        let h = handoff(Uuid::new_v4(), Utc::now());
        let back: HandoffRecord =
            serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!((back.handoff_id, *back.secret), (h.handoff_id, *h.secret));
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let rec = record(Utc::now(), Duration::zero());
        let out = format!("{rec:?}");
        assert!(out.contains("[redacted]"));
        assert!(!out.contains("171, 171"), "session key leaked: {out}");
        assert!(!out.contains("205, 205"), "cert hash leaked: {out}");
        let h = handoff(Uuid::new_v4(), Utc::now());
        let out = format!("{h:?}");
        assert!(out.contains("[redacted]") && !out.contains("7, 7"));
    }
}
