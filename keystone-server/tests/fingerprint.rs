//! HWID anomaly signal: same account, different fingerprint, short
//! window → flagged. Same fingerprint or outside the window → not.

use chrono::{Duration, Utc};
use keystone_server::SessionStore;

#[test]
fn same_fingerprint_is_not_anomalous() {
    let store = SessionStore::new();
    let now = Utc::now();
    let hw = [1u8; 32];
    assert!(!store.check_fingerprint("alice", hw, now, Duration::minutes(10)));
    assert!(!store.check_fingerprint(
        "alice",
        hw,
        now + Duration::minutes(1),
        Duration::minutes(10)
    ));
}

#[test]
fn different_fingerprint_inside_window_is_anomalous() {
    let store = SessionStore::new();
    let now = Utc::now();
    store.check_fingerprint("alice", [1u8; 32], now, Duration::minutes(10));
    assert!(store.check_fingerprint(
        "alice",
        [2u8; 32],
        now + Duration::minutes(2),
        Duration::minutes(10)
    ));
}

#[test]
fn different_fingerprint_outside_window_is_not_anomalous() {
    let store = SessionStore::new();
    let now = Utc::now();
    store.check_fingerprint("alice", [1u8; 32], now, Duration::minutes(10));
    assert!(!store.check_fingerprint(
        "alice",
        [2u8; 32],
        now + Duration::minutes(30),
        Duration::minutes(10)
    ));
}

#[test]
fn fingerprints_are_per_account() {
    let store = SessionStore::new();
    let now = Utc::now();
    store.check_fingerprint("alice", [1u8; 32], now, Duration::minutes(10));
    // Bob's first sighting is never anomalous.
    assert!(!store.check_fingerprint("bob", [9u8; 32], now, Duration::minutes(10)));
}
