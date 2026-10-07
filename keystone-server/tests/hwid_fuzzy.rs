//! Fuzzy component-based machine binding: the component set an exchange
//! binds, the weighted scoring that accepts near-matches, the self-heal
//! that stops upgrades from burning resets, and the below-threshold
//! refusal. The legacy single-hash path lives in `hwid.rs`.

mod common;

use axum::http::StatusCode;
use common::*;
use keystone_core::wire::{
    AccountInfoBody, ErrorCode, ExchangeRequest, HwidComponent, HwidComponentKind, HwidProbe,
    HwidResetBody, HwidResetRequest, hwid_match_score, match_hwid_probe, paths,
};
use keystone_server::AuditEvent;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MACHINE_A: [u8; 32] = [3; 32];

/// A harness over a machine-binding backend whose admin router accepts
/// [`ADMIN_TOKEN`].
async fn hwid_rig() -> (Harness, axum::Router) {
    let source = TestSource::standard();
    source.bind_machines();
    let h = harness_with(source, |b| {
        b.admin_token(keystone_server::AdminToken::new(ADMIN_TOKEN).unwrap())
    })
    .await;
    let admin = h.admin_app();
    (h, admin)
}

/// `GET /accounts/{name}` with an optional admin token header.
async fn account_info(
    admin: &axum::Router,
    name: &str,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    use axum::body::Body;
    use axum::http::Request;
    use keystone_core::wire::{PROTOCOL_HEADER, PROTOCOL_VERSION};
    let mut req =
        Request::get(paths::account(name)).header(PROTOCOL_HEADER, PROTOCOL_VERSION.to_string());
    if let Some(token) = token {
        req = req.header(keystone_core::wire::ADMIN_TOKEN_HEADER, token);
    }
    let (status, bytes) = send(admin, req.body(Body::empty()).unwrap()).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn from_machine(hwid: [u8; 32]) -> ExchangeRequest {
    ExchangeRequest {
        hwid,
        ..exchange_req(ACCOUNT, SECRET, PRODUCT)
    }
}

fn lock_of(hwid: [u8; 32]) -> [u8; 32] {
    Sha256::digest(hwid).into()
}

fn reset(token: &str, account: &str) -> HwidResetRequest {
    HwidResetRequest {
        admin_token: Zeroizing::new(token.to_string()),
        account: account.to_string(),
    }
}

/// One byte per kind keeps sets readable; a "changed" component flips its byte.
const FULL: [u8; 6] = [1, 2, 3, 4, 5, 6];
const KINDS: [HwidComponentKind; 6] = [
    HwidComponentKind::SmbiosUuid,
    HwidComponentKind::BoardSerial,
    HwidComponentKind::DiskSerial,
    HwidComponentKind::MachineGuid,
    HwidComponentKind::MacAddress,
    HwidComponentKind::CpuName,
];

fn set(bytes: [u8; 6]) -> Vec<HwidComponent> {
    KINDS
        .into_iter()
        .zip(bytes)
        .map(|(kind, byte)| HwidComponent {
            kind,
            hash: [byte; 32],
        })
        .collect()
}

/// `bytes` with one component changed.
fn with_changed(bytes: [u8; 6], kind: HwidComponentKind, byte: u8) -> [u8; 6] {
    let index = KINDS.iter().position(|k| *k == kind).unwrap();
    let mut next = bytes;
    next[index] = byte;
    next
}

fn probe(bytes: [u8; 6]) -> HwidProbe {
    HwidProbe {
        components: set(bytes),
    }
}

fn from_components(bytes: [u8; 6]) -> ExchangeRequest {
    ExchangeRequest {
        components: Some(set(bytes)),
        ..exchange_req(ACCOUNT, SECRET, PRODUCT)
    }
}

/// Weight of a full set: 4+4+2+2+1+1.
const TOTAL: f64 = 14.0;

fn score(stored: [u8; 6], probe: [u8; 6]) -> f64 {
    hwid_match_score(&set(stored), &set(probe))
}

#[test]
fn the_score_math_follows_the_weights() {
    // Identical sets score 1; disjoint kinds score 0.
    assert_eq!(score(FULL, FULL), 1.0);
    assert_eq!(hwid_match_score(&set(FULL), &[]), 0.0);

    // One low-weight component (MAC, 1) changed: 13/14 ≈ 0.93 — accepted.
    let mac_changed = with_changed(FULL, HwidComponentKind::MacAddress, 0xaa);
    assert_eq!(score(FULL, mac_changed), 13.0 / TOTAL);

    // One medium component (disk, 2) changed: 12/14 ≈ 0.86 — accepted.
    let disk_changed = with_changed(FULL, HwidComponentKind::DiskSerial, 0xbb);
    assert_eq!(score(FULL, disk_changed), 12.0 / TOTAL);

    // A reinstall (MachineGuid, 2) alone: 12/14 — accepted.
    let guid_changed = with_changed(FULL, HwidComponentKind::MachineGuid, 0xcc);
    assert_eq!(score(FULL, guid_changed), 12.0 / TOTAL);

    // Motherboard swapped (SMBIOS UUID + board serial, 8): 6/14 ≈ 0.43 —
    // rejected, and rejected even with everything else identical.
    let mut board = with_changed(FULL, HwidComponentKind::SmbiosUuid, 0xdd);
    board = with_changed(board, HwidComponentKind::BoardSerial, 0xee);
    assert_eq!(score(FULL, board), 6.0 / TOTAL);

    // Board plus disk (10): 4/14 ≈ 0.29 — rejected.
    let board_disk = with_changed(board, HwidComponentKind::DiskSerial, 0xff);
    assert_eq!(score(FULL, board_disk), 4.0 / TOTAL);

    // Only kinds present in both sets score: a probe with just the MAC
    // matching a full stored set is 1/1 = 1.0, and with a wrong MAC 0/1.
    let mac_only = vec![set(FULL)[4]];
    assert_eq!(hwid_match_score(&set(FULL), &mac_only), 1.0);
    let wrong_mac = vec![set(mac_changed)[4]];
    assert_eq!(hwid_match_score(&set(FULL), &wrong_mac), 0.0);
}

#[test]
fn the_threshold_classifies_each_case() {
    use keystone_core::wire::HwidMatch;
    let accept = |stored, probe| match match_hwid_probe(&set(stored), &set(probe)) {
        HwidMatch::Accepted { healed, .. } => healed,
        HwidMatch::Rejected { score } => panic!("rejected at {score}"),
    };
    let reject = |stored, probe| match match_hwid_probe(&set(stored), &set(probe)) {
        HwidMatch::Rejected { .. } => {}
        HwidMatch::Accepted { score, .. } => panic!("accepted at {score}"),
    };
    let mac_changed = with_changed(FULL, HwidComponentKind::MacAddress, 0xaa);
    let mut board = with_changed(FULL, HwidComponentKind::SmbiosUuid, 0xdd);
    board = with_changed(board, HwidComponentKind::BoardSerial, 0xee);
    let both_low = with_changed(mac_changed, HwidComponentKind::CpuName, 0x99);
    // 12/14 ≈ 0.857 ≥ 0.75: both low-weight parts may drift together.
    accept(FULL, both_low);
    accept(FULL, mac_changed);
    // 10/14 ≈ 0.714 < 0.75: a single 4-weight chassis change is refused,
    // so the two-step chassis walk (change board → heal, change smbios →
    // heal) never gets its first heal.
    let board_only = with_changed(FULL, HwidComponentKind::BoardSerial, 0xee);
    reject(FULL, board_only);
    // 6/14 ≈ 0.429 < 0.75: the chassis identity must agree.
    reject(FULL, board);

    // The heal adopts the probe's hashes for changed matched kinds only.
    let healed = accept(FULL, mac_changed);
    assert_eq!(healed, set(mac_changed));
    let healed = accept(FULL, both_low);
    assert_eq!(healed, set(both_low));
}

#[tokio::test]
async fn the_first_component_exchange_stores_the_set_and_it_matches_thereafter() {
    let (h, _) = hwid_rig().await;
    assert_eq!(h.source.hwid_components(ACCOUNT), None);

    let (first, _) = exchange_with(&h, from_components(FULL)).await;
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));

    // An identical probe is accepted and changes nothing.
    let (second, _) = exchange_with(&h, from_components(FULL)).await;
    assert_ne!(first.id, second.id);
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));
    heartbeat_ok(&h, &second).await;
}

#[tokio::test]
async fn a_low_weight_change_is_accepted_and_self_heals() {
    let (h, _) = hwid_rig().await;
    exchange_with(&h, from_components(FULL)).await;

    let upgraded = with_changed(FULL, HwidComponentKind::MacAddress, 0xaa);
    let (session, _) = exchange_with(&h, from_components(upgraded)).await;
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(upgraded)));
    heartbeat_ok(&h, &session).await;

    // The pre-upgrade probe now mismatches the healed MAC — but at 13/14 it
    // still scores above the threshold, so it is accepted and heals back.
    // (Score symmetry: a healed one-component drift cannot reject the old
    // probe without also rejecting the upgrade that caused it.)
    let (session, _) = exchange_with(&h, from_components(FULL)).await;
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));
    heartbeat_ok(&h, &session).await;
}

#[tokio::test]
async fn a_motherboard_change_is_refused_with_the_score_logged() {
    let (h, _) = hwid_rig().await;
    exchange_with(&h, from_components(FULL)).await;

    let mut new_board = with_changed(FULL, HwidComponentKind::SmbiosUuid, 0xdd);
    new_board = with_changed(new_board, HwidComponentKind::BoardSerial, 0xee);
    let (status, body) = post(&h.app, "/exchange", &from_components(new_board)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::HwidMismatch)
    );
    // The refusal neither heals nor rebinds, and leaves no session behind.
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));
    assert_eq!(
        keystone_server::SessionStore::ids_for_account(h.store.as_ref(), ACCOUNT)
            .await
            .unwrap()
            .len(),
        1
    );
    // The audit carries the exact score: 6 of 14 weight matched.
    let events = h.audit.events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            AuditEvent::HwidFuzzyRejected { account, score }
                if account == ACCOUNT && *score == Some(6.0 / 14.0)
        )),
        "fuzzy reject with score logged: {events:?}"
    );
    assert!(events.iter().any(|e| matches!(
        e,
        AuditEvent::ExchangeDenied {
            reason: ErrorCode::HwidMismatch,
            ..
        }
    )));
}

/// A single 4-weight chassis change (10/14 ≈ 0.714 < 0.75) is refused
/// and leaves the stored set untouched: no heal, no walk.
#[tokio::test]
async fn a_single_chassis_change_is_refused_without_healing() {
    let (h, _) = hwid_rig().await;
    exchange_with(&h, from_components(FULL)).await;

    let board_changed = with_changed(FULL, HwidComponentKind::BoardSerial, 0xee);
    let (status, body) = post(&h.app, "/exchange", &from_components(board_changed)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::HwidMismatch)
    );
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));
    // The SMBIOS UUID alone fares no better.
    let smbios_changed = with_changed(FULL, HwidComponentKind::SmbiosUuid, 0xdd);
    let (status, body) = post(&h.app, "/exchange", &from_components(smbios_changed)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::HwidMismatch)
    );
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));
}

/// The two-step chassis walk is dead: step one (board serial) is refused,
/// so step two (SMBIOS UUID) scores against the UNHEALED set and misses
/// both chassis kinds — 6/14, refused.
#[tokio::test]
async fn a_two_step_chassis_walk_is_refused_step_by_step() {
    let (h, _) = hwid_rig().await;
    exchange_with(&h, from_components(FULL)).await;

    // Step one: change the board serial. Refused, nothing heals.
    let step_one = with_changed(FULL, HwidComponentKind::BoardSerial, 0xee);
    let (status, body) = post(&h.app, "/exchange", &from_components(step_one)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::HwidMismatch)
    );
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));

    // Step two: change the SMBIOS UUID too. Had step one healed, this
    // would score 10/14 against the healed set; against the unhealed set
    // it scores 6/14 and is refused as well.
    let step_two = with_changed(step_one, HwidComponentKind::SmbiosUuid, 0xdd);
    let (status, body) = post(&h.app, "/exchange", &from_components(step_two)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::HwidMismatch)
    );
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));
}

/// Multi-NIC machines: a probe may carry several MACs, the MAC kind
/// scores once and matches when ANY probe MAC equals ANY stored MAC, and
/// the heal replaces the stored MAC set with the probe's.
#[tokio::test]
async fn multi_nic_probes_match_on_any_mac_and_heal_the_whole_set() {
    use keystone_core::wire::HwidMatch;
    let mac = |byte: u8| HwidComponent {
        kind: HwidComponentKind::MacAddress,
        hash: [byte; 32],
    };
    // Duplicate MACs pass probe validation; duplicates of any other kind
    // still fail.
    let mut two_macs = set(FULL);
    two_macs.insert(5, mac(0xaa));
    HwidProbe {
        components: two_macs.clone(),
    }
    .validate()
    .expect("two MACs validate");

    // Any-match scoring: stored {5}, probe {0xaa, 5} matches via the
    // shared MAC and counts the kind once (weight 1 of 14 total).
    assert_eq!(hwid_match_score(&set(FULL), &two_macs), 1.0);
    // No shared MAC: the kind mismatches, still counted once: 13/14.
    let mut foreign_macs = set(with_changed(FULL, HwidComponentKind::MacAddress, 0xbb));
    foreign_macs.insert(5, mac(0xaa));
    assert_eq!(hwid_match_score(&set(FULL), &foreign_macs), 13.0 / TOTAL);

    // The heal adopts the probe's MAC set wholesale.
    let healed = match match_hwid_probe(&set(FULL), &two_macs) {
        HwidMatch::Accepted { healed, .. } => healed,
        HwidMatch::Rejected { score } => panic!("rejected at {score}"),
    };
    assert_eq!(healed, two_macs);

    // End to end: the second NIC may come and go without a reset.
    let (h, _) = hwid_rig().await;
    exchange_with(&h, from_components(FULL)).await;
    let mut req = from_components(FULL);
    req.components = Some(two_macs.clone());
    let (session, _) = exchange_with(&h, req).await;
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(two_macs));
    heartbeat_ok(&h, &session).await;
    let (session, _) = exchange_with(&h, from_components(FULL)).await;
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));
    heartbeat_ok(&h, &session).await;
}

#[tokio::test]
async fn probe_validation_rejects_empty_and_duplicate_kinds() {
    let (h, _) = hwid_rig().await;
    let mut req = exchange_req(ACCOUNT, SECRET, PRODUCT);
    req.components = Some(vec![]);
    let (status, body) = post(&h.app, "/exchange", &req).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::BAD_REQUEST, ErrorCode::BadRequest)
    );

    let mut dup = set(FULL);
    dup.push(dup[0]);
    req.components = Some(dup);
    let (status, body) = post(&h.app, "/exchange", &req).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::BAD_REQUEST, ErrorCode::BadRequest)
    );
    assert_eq!(h.source.hwid_components(ACCOUNT), None);
}

#[tokio::test]
async fn a_reset_clears_the_component_set_and_the_next_probe_rebinds() {
    let (h, admin) = hwid_rig().await;
    let (old, _) = exchange_with(&h, from_components(FULL)).await;

    let (status, body) = post(&admin, paths::HWID_RESET, &reset(ADMIN_TOKEN, ACCOUNT)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        serde_json::from_value::<HwidResetBody>(body)
            .unwrap()
            .was_locked
    );
    assert_eq!(h.source.hwid_components(ACCOUNT), None);
    // The old machine's sessions die with the lock.
    let (status, body) = heartbeat(&h, &old).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::SessionRevoked)
    );

    let upgraded = with_changed(FULL, HwidComponentKind::DiskSerial, 0xbb);
    let (session, _) = exchange_with(&h, from_components(upgraded)).await;
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(upgraded)));
    heartbeat_ok(&h, &session).await;
}

#[tokio::test]
async fn account_info_reports_a_component_lock() {
    let (h, admin) = hwid_rig().await;
    let (status, body) = account_info(&admin, ACCOUNT, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !serde_json::from_value::<AccountInfoBody>(body)
            .unwrap()
            .hwid_locked
    );

    exchange_with(&h, from_components(FULL)).await;
    let (status, body) = account_info(&admin, ACCOUNT, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        serde_json::from_value::<AccountInfoBody>(body)
            .unwrap()
            .hwid_locked
    );
}

#[tokio::test]
async fn fuzzy_and_legacy_locks_reject_the_other_flavor() {
    let (h, admin) = hwid_rig().await;
    // A legacy exchange binds the strict lock; a component probe from any
    // machine must not rebind the fuzzy flavor on top of it.
    exchange_with(&h, from_machine(MACHINE_A)).await;
    assert_eq!(h.source.hwid_lock(ACCOUNT), Some(lock_of(MACHINE_A)));
    assert_eq!(h.source.hwid_components(ACCOUNT), None);

    let (status, body) = post(&h.app, "/exchange", &from_components(FULL)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::HwidMismatch)
    );
    // The rejection binds nothing and touches neither store.
    assert_eq!(h.source.hwid_components(ACCOUNT), None);
    assert_eq!(h.source.hwid_lock(ACCOUNT), Some(lock_of(MACHINE_A)));

    // The reverse direction, after an admin reset (the migration path):
    // a component-bound account rejects a legacy single-hash request.
    let (status, body) = post(&admin, paths::HWID_RESET, &reset(ADMIN_TOKEN, ACCOUNT)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    exchange_with(&h, from_components(FULL)).await;
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));
    assert_eq!(h.source.hwid_lock(ACCOUNT), None);

    let (status, body) = post(&h.app, "/exchange", &from_machine(MACHINE_A)).await;
    assert_eq!(
        (status, code(&body)),
        (StatusCode::FORBIDDEN, ErrorCode::HwidMismatch)
    );
    assert_eq!(h.source.hwid_lock(ACCOUNT), None);
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(FULL)));
}

/// A fuzzy account stays bound across a server restart: the set persists.
#[tokio::test]
async fn the_component_set_survives_a_restart() {
    let (h, _) = hwid_rig().await;
    exchange_with(&h, from_components(FULL)).await;
    let h = h.restarted().await;

    let upgraded = with_changed(FULL, HwidComponentKind::CpuName, 0x99);
    let (session, _) = exchange_with(&h, from_components(upgraded)).await;
    assert_eq!(h.source.hwid_components(ACCOUNT), Some(set(upgraded)));
    heartbeat_ok(&h, &session).await;
}

/// LocalAccounts (the file backend) fuzzy path: bind, heal, reject, clear.
#[tokio::test]
async fn local_accounts_match_and_heal_atomically() {
    use keystone_core::{AccountRecord, EntitlementSource, HwidVerdict};
    use keystone_server::accounts::LocalAccounts;

    let dir = temp_dir("fuzzy-accounts");
    let path = dir.join("accounts.json");
    keystone_core::AccountFile {
        accounts: vec![AccountRecord {
            name: ACCOUNT.into(),
            secret_hash: "$argon2id$v=19$fake".into(),
            entitlements: vec![],
            cert_sha256: None,
            hwid_lock: None,
            hwid_components: None,
        }],
    }
    .save(&path)
    .unwrap();
    let backend = LocalAccounts::open(path.clone());

    // First probe binds.
    assert_eq!(
        backend.match_hwid(ACCOUNT, &probe(FULL)).await.unwrap(),
        Some(HwidVerdict::Accepted { updated: true })
    );
    assert_eq!(
        backend.hwid_components(ACCOUNT).await.unwrap(),
        Some(set(FULL))
    );

    // Identical probe: accepted, no update.
    assert_eq!(
        backend.match_hwid(ACCOUNT, &probe(FULL)).await.unwrap(),
        Some(HwidVerdict::Accepted { updated: false })
    );

    // A reinstall (MachineGuid) is tolerated and healed, and the heal is
    // on disk: a fresh backend over the same file sees the new set.
    let reinstalled = with_changed(FULL, HwidComponentKind::MachineGuid, 0xcc);
    assert_eq!(
        backend
            .match_hwid(ACCOUNT, &probe(reinstalled))
            .await
            .unwrap(),
        Some(HwidVerdict::Accepted { updated: true })
    );
    let reloaded = LocalAccounts::open(path.clone());
    assert_eq!(
        reloaded.hwid_components(ACCOUNT).await.unwrap(),
        Some(set(reinstalled))
    );

    // Below threshold: rejected, stored set untouched.
    let mut stranger = with_changed(reinstalled, HwidComponentKind::SmbiosUuid, 0xdd);
    stranger = with_changed(stranger, HwidComponentKind::BoardSerial, 0xee);
    assert_eq!(
        backend.match_hwid(ACCOUNT, &probe(stranger)).await.unwrap(),
        Some(HwidVerdict::Rejected)
    );
    assert_eq!(
        backend.hwid_components(ACCOUNT).await.unwrap(),
        Some(set(reinstalled))
    );

    // Unknown accounts report Unknown; clear frees the account.
    assert_eq!(
        backend.match_hwid("nobody", &probe(FULL)).await.unwrap(),
        Some(HwidVerdict::Unknown)
    );
    assert_eq!(backend.clear_hwid_lock(ACCOUNT).await.unwrap(), Some(true));
    assert_eq!(backend.hwid_components(ACCOUNT).await.unwrap(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// LocalAccounts enforces the flavor lock in both directions: a
/// legacy-locked account rejects component probes, a component-bound
/// account rejects legacy single-hash requests, and only an admin reset
/// (clearing both stores) migrates an account between flavors.
#[tokio::test]
async fn local_accounts_reject_the_other_lock_flavor() {
    use keystone_core::{AccountRecord, EntitlementSource, HwidVerdict};
    use keystone_server::accounts::LocalAccounts;

    let dir = temp_dir("flavor-lock");
    let path = dir.join("accounts.json");
    keystone_core::AccountFile {
        accounts: vec![AccountRecord {
            name: ACCOUNT.into(),
            secret_hash: "$argon2id$v=19$fake".into(),
            entitlements: vec![],
            cert_sha256: None,
            hwid_lock: None,
            hwid_components: None,
        }],
    }
    .save(&path)
    .unwrap();
    let backend = LocalAccounts::open(path);

    // Legacy-locked: the first component probe is rejected and binds
    // nothing.
    let lock = lock_of(MACHINE_A);
    assert_eq!(backend.bind_hwid(ACCOUNT, lock).await.unwrap(), Some(lock));
    assert_eq!(
        backend.match_hwid(ACCOUNT, &probe(FULL)).await.unwrap(),
        Some(HwidVerdict::Rejected)
    );
    assert_eq!(backend.hwid_components(ACCOUNT).await.unwrap(), None);
    // The strict lock itself still gates.
    assert_eq!(
        backend.bind_hwid(ACCOUNT, lock_of([9; 32])).await.unwrap(),
        Some(lock)
    );

    // Reset migrates: both stores clear, the fuzzy flavor can bind.
    assert_eq!(backend.clear_hwid_lock(ACCOUNT).await.unwrap(), Some(true));
    assert_eq!(
        backend.match_hwid(ACCOUNT, &probe(FULL)).await.unwrap(),
        Some(HwidVerdict::Accepted { updated: true })
    );

    // Component-bound: a legacy single-hash request is rejected (a lock
    // guaranteed to differ) and the strict store stays unset.
    let foreign = backend
        .bind_hwid(ACCOUNT, lock_of(MACHINE_A))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(foreign, lock_of(MACHINE_A));
    assert_eq!(
        backend.hwid_components(ACCOUNT).await.unwrap(),
        Some(set(FULL))
    );
    // The component set still matches and heals.
    let upgraded = with_changed(FULL, HwidComponentKind::CpuName, 0x99);
    assert_eq!(
        backend.match_hwid(ACCOUNT, &probe(upgraded)).await.unwrap(),
        Some(HwidVerdict::Accepted { updated: true })
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
