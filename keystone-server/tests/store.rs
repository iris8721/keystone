//! SessionStore internals: the session key is the proof-of-possession
//! secret for every MAC'd route — Debug output must never carry it.

use chrono::{DateTime, Duration, Utc};
use keystone_core::Lease;
use keystone_core::{ConsumedSet, DeadReason, SessionState};
use keystone_server::SessionStore;
use keystone_server::store::SessionRecord;
use uuid::Uuid;

fn record(now: DateTime<Utc>, cert_sha256: Option<[u8; 32]>) -> SessionRecord {
    SessionRecord {
        session_id: Uuid::new_v4(),
        account: "dev".into(),
        product: "dev-product".into(),
        hwid_hash: [0x11u8; 32],
        session_key: [0xABu8; 32],
        entitlement_expires_at: now + Duration::days(30),
        cert_sha256,
        state: SessionState::Active {
            lease: Lease {
                session_id: Uuid::new_v4(),
                granted_at: now,
                expires_at: now + Duration::seconds(300),
                grace_period: Duration::seconds(60),
            },
        },
        consumed: ConsumedSet::new(),
        created_at: now,
    }
}

#[test]
fn session_record_debug_redacts_session_key() {
    let rec = record(Utc::now(), None);
    let out = format!("{rec:?}");
    assert!(
        out.contains("[redacted]"),
        "session_key must be redacted: {out}"
    );
    // 0xAB = 171 — the raw key bytes must not appear in any form.
    assert!(
        !out.contains("171"),
        "session_key bytes leaked into Debug: {out}"
    );
}

#[test]
fn session_record_debug_shows_cert_binding_presence_only() {
    let out = format!("{:?}", record(Utc::now(), Some([0xCDu8; 32])));
    assert!(out.contains("cert_sha256: \"present\""), "{out}");
    // The hash itself stays out of the line — 0xCD repeated would
    // render as a run of "205, 205".
    assert!(
        !out.contains("205, 205"),
        "cert hash leaked into Debug: {out}"
    );
    let out = format!("{:?}", record(Utc::now(), None));
    assert!(out.contains("cert_sha256: \"absent\""), "{out}");
}

/// Key-compromise response: every live session dies, already-dead
/// records keep their original reason, and the count is what was
/// actually killed.
#[test]
fn revoke_all_kills_live_sessions_and_keeps_dead_reasons() {
    let store = SessionStore::new();
    let now = Utc::now();
    let live = record(now, None);
    let live_id = live.session_id;
    let mut expired = record(now, None);
    expired.state.kill(DeadReason::Expired);
    let expired_id = expired.session_id;
    store.insert(live);
    store.insert(expired);

    assert_eq!(store.revoke_all(DeadReason::Revoked), 1);
    assert!(matches!(
        store.get(&live_id).unwrap().state,
        SessionState::Dead {
            reason: DeadReason::Revoked
        }
    ));
    assert!(matches!(
        store.get(&expired_id).unwrap().state,
        SessionState::Dead {
            reason: DeadReason::Expired
        }
    ));
    // Nothing left to kill.
    assert_eq!(store.revoke_all(DeadReason::Revoked), 0);
}
