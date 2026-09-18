//! SessionStore internals: the session key is the proof-of-possession
//! secret for every MAC'd route — Debug output must never carry it.

use chrono::{Duration, Utc};
use keystone_core::{ConsumedSet, SessionState};
use keystone_server::store::SessionRecord;
use keystone_core::Lease;
use uuid::Uuid;

#[test]
fn session_record_debug_redacts_session_key() {
    let now = Utc::now();
    let rec = SessionRecord {
        session_id: Uuid::new_v4(),
        account: "dev".into(),
        product: "dev-product".into(),
        hwid_hash: [0x11u8; 32],
        session_key: [0xABu8; 32],
        entitlement_expires_at: now + Duration::days(30),
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
    };
    let out = format!("{rec:?}");
    assert!(out.contains("[redacted]"), "session_key must be redacted: {out}");
    // 0xAB = 171 — the raw key bytes must not appear in any form.
    assert!(
        !out.contains("171"),
        "session_key bytes leaked into Debug: {out}"
    );
}
