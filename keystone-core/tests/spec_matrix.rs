//! The writeup's self-test matrix, executable:
//! altered artifacts, expired grants, wrong-product auth, reused
//! one-time responses, revoked sessions — all must be rejected.

use chrono::{Duration, Utc};
use keystone_core::*;
use uuid::Uuid;

fn setup() -> (Issuer, Challenge, Uuid) {
    let issuer = Issuer::generate();
    let challenge = Challenge::fresh(Duration::seconds(30));
    let session = Uuid::new_v4();
    (issuer, challenge, session)
}

fn issue_valid(issuer: &Issuer, challenge: &Challenge, session: Uuid) -> Envelope {
    let now = Utc::now();
    Envelope::issue(
        issuer,
        IssueSpec {
            challenge: challenge.nonce,
            session_id: session,
            audience: "keystone-server".to_string(),
            operation: "payload.download".to_string(),
            issued_at: now,
            expires_at: now + Duration::seconds(60),
            body: b"grant-body".to_vec(),
        },
    )
}

fn expect_for<'a>(
    challenge: &'a Challenge,
    session: &'a Uuid,
    now: chrono::DateTime<Utc>,
) -> Expectation<'a> {
    Expectation {
        challenge: &challenge.nonce,
        session_id: session,
        audience: "keystone-server",
        operation: "payload.download",
        now,
    }
}

#[test]
fn valid_envelope_verifies() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let now = Utc::now();
    env.verify(&issuer.verifying_key(), &expect_for(&challenge, &session, now))
        .expect("valid envelope must verify");
}

#[test]
fn altered_body_rejected() {
    let (issuer, challenge, session) = setup();
    let mut env = issue_valid(&issuer, &challenge, session);
    env.body = b"forged-body".to_vec(); // signature no longer matches
    let now = Utc::now();
    assert!(matches!(
        env.verify(&issuer.verifying_key(), &expect_for(&challenge, &session, now)),
        Err(KeystoneError::InvalidSignature)
    ));
}

#[test]
fn replayed_old_response_rejected() {
    // Attacker holds a valid signed response from a previous session.
    // New request carries a new challenge — old response must fail.
    let (issuer, old_challenge, session) = setup();
    let env = issue_valid(&issuer, &old_challenge, session);

    let new_challenge = Challenge::fresh(Duration::seconds(30));
    let now = Utc::now();
    assert!(matches!(
        env.verify(
            &issuer.verifying_key(),
            &expect_for(&new_challenge, &session, now)
        ),
        Err(KeystoneError::ChallengeMismatch)
    ));
}

#[test]
fn replayed_accepted_response_rejected() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let now = Utc::now();

    env.verify(&issuer.verifying_key(), &expect_for(&challenge, &session, now))
        .unwrap();

    let mut consumed = ConsumedSet::new();
    consumed.consume(challenge.nonce, env.expires_at).unwrap();

    // Same response submitted again — already consumed.
    assert!(matches!(
        consumed.consume(challenge.nonce, env.expires_at),
        Err(KeystoneError::AlreadyConsumed)
    ));
}

#[test]
fn expired_envelope_rejected() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let later = env.expires_at + Duration::seconds(1);
    assert!(matches!(
        env.verify(
            &issuer.verifying_key(),
            &expect_for(&challenge, &session, later)
        ),
        Err(KeystoneError::Expired)
    ));

    // AT the boundary the envelope is already dead — `now >=
    // expires_at`, not `>`. One millisecond before it still verifies.
    assert!(matches!(
        env.verify(
            &issuer.verifying_key(),
            &expect_for(&challenge, &session, env.expires_at)
        ),
        Err(KeystoneError::Expired)
    ));
    env.verify(
        &issuer.verifying_key(),
        &expect_for(
            &challenge,
            &session,
            env.expires_at - Duration::milliseconds(1),
        ),
    )
    .expect("envelope must verify one ms before expiry");
}

#[test]
fn wrong_audience_rejected() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let now = Utc::now();
    let mut expect = expect_for(&challenge, &session, now);
    expect.audience = "some-other-service";
    assert!(matches!(
        env.verify(&issuer.verifying_key(), &expect),
        Err(KeystoneError::AudienceMismatch { .. })
    ));
}

#[test]
fn wrong_operation_rejected() {
    // Wrong-product / wrong-op authorization must not cross over.
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let now = Utc::now();
    let mut expect = expect_for(&challenge, &session, now);
    expect.operation = "feature.esp";
    assert!(matches!(
        env.verify(&issuer.verifying_key(), &expect),
        Err(KeystoneError::OperationMismatch { .. })
    ));
}

#[test]
fn wrong_session_rejected() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let other_session = Uuid::new_v4();
    let now = Utc::now();
    assert!(matches!(
        env.verify(
            &issuer.verifying_key(),
            &expect_for(&challenge, &other_session, now)
        ),
        Err(KeystoneError::SessionMismatch)
    ));
}

#[test]
fn wrong_issuer_key_rejected() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let attacker_issuer = Issuer::generate();
    let now = Utc::now();
    assert!(matches!(
        env.verify(
            &attacker_issuer.verifying_key(),
            &expect_for(&challenge, &session, now)
        ),
        Err(KeystoneError::InvalidSignature)
    ));
}

#[test]
fn response_mac_binds_nonce_and_session() {
    let session_key = b"session-secret-material";
    let nonce = [7u8; 32];
    let body = b"payload-bytes";

    let mac = mac_response(session_key, &nonce, body);
    verify_response_mac(session_key, &nonce, body, &mac).unwrap();

    // Different nonce — replay into another request fails.
    let other_nonce = [9u8; 32];
    assert!(matches!(
        verify_response_mac(session_key, &other_nonce, body, &mac),
        Err(KeystoneError::InvalidMac)
    ));

    // Different session key — capture replayed into another session fails.
    assert!(matches!(
        verify_response_mac(b"other-session", &nonce, body, &mac),
        Err(KeystoneError::InvalidMac)
    ));

    // Altered body fails.
    assert!(matches!(
        verify_response_mac(session_key, &nonce, b"tampered", &mac),
        Err(KeystoneError::InvalidMac)
    ));
}

#[test]
fn payload_key_requires_live_secret() {
    let secret = b"server-issued-license-secret";
    let salt = b"session-salt";
    let key = derive_payload_key(secret, salt, b"aimbot:1.4.2");

    // Deterministic for same inputs.
    assert_eq!(key, derive_payload_key(secret, salt, b"aimbot:1.4.2"));

    // Different context → different key (product/version binding).
    assert_ne!(key, derive_payload_key(secret, salt, b"esp:1.4.2"));

    // Without the server secret, no key.
    assert_ne!(key, derive_payload_key(b"guessed", salt, b"aimbot:1.4.2"));
}

#[test]
fn grace_deadline_is_fixed() {
    let now = Utc::now();
    let lease = Lease {
        session_id: Uuid::new_v4(),
        granted_at: now,
        expires_at: now + Duration::minutes(10),
        grace_period: Duration::minutes(2),
    };
    let mut state = SessionState::Active {
        lease: lease.clone(),
    };

    // First failure at t+0: deadline = t+2min.
    state.on_transient_failure(now);
    assert!(state.authorize(now + Duration::seconds(60)).is_ok());

    // Second failure at t+90s must NOT extend the deadline.
    state.on_transient_failure(now + Duration::seconds(90));
    assert!(matches!(
        state.authorize(now + Duration::seconds(121)),
        Err(KeystoneError::GraceExhausted)
    ));
}

#[test]
fn heartbeat_success_clears_grace() {
    let now = Utc::now();
    let lease = Lease {
        session_id: Uuid::new_v4(),
        granted_at: now,
        expires_at: now + Duration::minutes(10),
        grace_period: Duration::minutes(2),
    };
    let mut state = SessionState::Active {
        lease: lease.clone(),
    };
    state.on_transient_failure(now);

    let renewed = Lease {
        granted_at: now + Duration::seconds(30),
        expires_at: now + Duration::minutes(10),
        ..lease
    };
    state.on_heartbeat_ok(renewed);

    // A later failure starts a FRESH grace window: deadline t0+60s+2min
    // = t0+180s. Probe strictly PAST the old deadline (t0+120s) — at
    // equality a never-cleared grace would still authorize, so the
    // probe must land where only a fresh window keeps the session up.
    state.on_transient_failure(now + Duration::seconds(60));
    assert!(state.authorize(now + Duration::seconds(121)).is_ok());
    // And past the NEW deadline it really is over.
    assert!(matches!(
        state.authorize(now + Duration::seconds(181)),
        Err(KeystoneError::GraceExhausted)
    ));
}

#[test]
fn explicit_rejection_kills_immediately() {
    let now = Utc::now();
    let lease = Lease {
        session_id: Uuid::new_v4(),
        granted_at: now,
        expires_at: now + Duration::minutes(10),
        grace_period: Duration::minutes(2),
    };
    let mut state = SessionState::Active { lease };
    state.kill(DeadReason::Revoked);
    assert!(matches!(
        state.authorize(now),
        Err(KeystoneError::Revoked)
    ));
}

#[test]
fn challenge_expiry() {
    let challenge = Challenge::fresh(Duration::seconds(30));
    let now = Utc::now();
    assert!(!challenge.is_expired(now));
    assert!(challenge.is_expired(now + Duration::seconds(31)));
    // Constant-time challenge comparison is exercised through
    // Envelope::verify — see replayed_old_response_rejected.

    // AT the boundary the challenge is already dead — `now >=
    // issued_at + ttl`, not `>`. One ms before it still lives.
    let deadline = challenge.issued_at + challenge.ttl;
    assert!(challenge.is_expired(deadline));
    assert!(!challenge.is_expired(deadline - Duration::milliseconds(1)));
}

#[test]
fn lease_expired_at_expiry() {
    // Lease::is_expired is `now >= expires_at`: AT the boundary the
    // lease is dead, one ms before it lives.
    let now = Utc::now();
    let lease = Lease {
        session_id: Uuid::new_v4(),
        granted_at: now,
        expires_at: now + Duration::seconds(60),
        grace_period: Duration::seconds(30),
    };
    assert!(!lease.is_expired(now + Duration::seconds(59)));
    assert!(lease.is_expired(lease.expires_at));
}

#[test]
fn consumed_set_evicts_expired() {
    let mut set = ConsumedSet::new();
    let now = Utc::now();
    set.consume([1u8; 32], now + Duration::seconds(10)).unwrap();
    set.consume([2u8; 32], now - Duration::seconds(10)).unwrap();
    // An entry expiring exactly AT `now` is dead weight — evicted.
    set.consume([3u8; 32], now).unwrap();
    assert_eq!(set.len(), 3);
    set.evict_expired(now);
    assert_eq!(set.len(), 1);
    assert!(set.is_consumed(&[1u8; 32]));
    assert!(!set.is_consumed(&[3u8; 32]));
}

/// Every field the signature claims to cover must actually be covered.
/// If any field were dropped from canonical_bytes, mutating it would
/// still verify — this sweep catches that.
#[test]
fn every_signed_field_is_actually_signed() {
    let (issuer, challenge, session) = setup();
    let base = issue_valid(&issuer, &challenge, session);
    let now = Utc::now();
    let key = issuer.verifying_key();

    // Mutating each field post-signing must break the signature.
    let mut e = base.clone();
    e.challenge = [0xAA; 32];
    assert!(matches!(
        e.verify(&key, &expect_for(&challenge, &session, now)),
        Err(KeystoneError::InvalidSignature)
    ));

    let mut e = base.clone();
    e.session_id = Uuid::new_v4();
    assert!(matches!(
        e.verify(&key, &expect_for(&challenge, &session, now)),
        Err(KeystoneError::InvalidSignature)
    ));

    let mut e = base.clone();
    e.audience = "forged".into();
    assert!(matches!(
        e.verify(&key, &expect_for(&challenge, &session, now)),
        Err(KeystoneError::InvalidSignature)
    ));

    let mut e = base.clone();
    e.operation = "forged".into();
    assert!(matches!(
        e.verify(&key, &expect_for(&challenge, &session, now)),
        Err(KeystoneError::InvalidSignature)
    ));

    // The killer case: extending expiry on a dead envelope. If
    // expires_at weren't signed, this would verify and resurrect it.
    let mut e = base.clone();
    e.expires_at = now + Duration::days(365);
    assert!(matches!(
        e.verify(&key, &expect_for(&challenge, &session, now)),
        Err(KeystoneError::InvalidSignature)
    ));

    let mut e = base.clone();
    e.issued_at = now - Duration::days(365);
    assert!(matches!(
        e.verify(&key, &expect_for(&challenge, &session, now)),
        Err(KeystoneError::InvalidSignature)
    ));

    let mut e = base;
    e.body = b"forged".to_vec();
    assert!(matches!(
        e.verify(&key, &expect_for(&challenge, &session, now)),
        Err(KeystoneError::InvalidSignature)
    ));
}

/// The manifest's build_id is signed like every other attested field —
/// a leaked build's attribution can't be rewritten without breaking
/// the signature.
#[test]
fn manifest_build_id_is_signed() {
    let issuer = Issuer::generate();
    let now = Utc::now();
    let manifest = Manifest {
        product: "prod".into(),
        version: "1.0.0".into(),
        build_id: "build-a1b2c3".into(),
        download_id: "dl-9f8e7d".into(),
        sha256: [0u8; 32],
        feature_grants: vec![],
        issued_at: now,
        expires_at: now + Duration::minutes(5),
    };
    let mut signed = SignedManifest::issue(&issuer, manifest);
    signed
        .verify(&issuer.verifying_key(), now)
        .expect("fresh manifest must verify");

    signed.manifest.build_id = "build-forged".into();
    assert!(matches!(
        signed.verify(&issuer.verifying_key(), now),
        Err(KeystoneError::InvalidSignature)
    ));
}

#[test]
fn envelope_survives_json_roundtrip() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let json = serde_json::to_vec(&env).unwrap();
    let back: Envelope = serde_json::from_slice(&json).unwrap();
    let now = Utc::now();
    back.verify(
        &issuer.verifying_key(),
        &expect_for(&challenge, &session, now),
    )
    .expect("round-tripped envelope must still verify");

    // Tamper inside the signed `audience` string: mutating a character
    // keeps the JSON valid AND parseable, so verify() is the only
    // thing that can catch it — a flip that broke the wire format
    // would prove nothing about the signature.
    let mut tampered = serde_json::to_value(&env).unwrap();
    tampered["audience"] = serde_json::json!("keystone-servfr");
    let tampered = serde_json::to_vec(&tampered).unwrap();
    let e: Envelope = serde_json::from_slice(&tampered)
        .expect("a string-field mutation must still parse");
    assert_ne!(e.audience, env.audience, "the tamper must have landed");
    assert!(matches!(
        e.verify(
            &issuer.verifying_key(),
            &expect_for(&challenge, &session, now)
        ),
        Err(KeystoneError::InvalidSignature)
    ));
}

#[test]
fn accept_once_pipeline() {
    // The real flow: verify, then consume. Second submission of the
    // same valid response must die at the consume step.
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let now = Utc::now();
    let key = issuer.verifying_key();
    let mut consumed = ConsumedSet::new();

    env.verify(&key, &expect_for(&challenge, &session, now)).unwrap();
    consumed.consume(challenge.nonce, env.expires_at).unwrap();

    // Replay: signature still valid, but the nonce is spent.
    env.verify(&key, &expect_for(&challenge, &session, now)).unwrap();
    assert!(matches!(
        consumed.consume(challenge.nonce, env.expires_at),
        Err(KeystoneError::AlreadyConsumed)
    ));
}

#[test]
fn lease_expiry_during_grace_is_expired_not_grace() {
    let now = Utc::now();
    let lease = Lease {
        session_id: Uuid::new_v4(),
        granted_at: now,
        expires_at: now + Duration::seconds(30),
        grace_period: Duration::minutes(5),
    };
    let mut state = SessionState::Active { lease };
    state.on_transient_failure(now);
    // Inside grace window but past lease expiry → Expired, not ok.
    assert!(matches!(
        state.authorize(now + Duration::seconds(31)),
        Err(KeystoneError::Expired)
    ));
}

#[test]
fn dead_state_stays_dead() {
    let now = Utc::now();
    let lease = Lease {
        session_id: Uuid::new_v4(),
        granted_at: now,
        expires_at: now + Duration::minutes(10),
        grace_period: Duration::minutes(2),
    };
    let mut state = SessionState::Active { lease: lease.clone() };
    state.kill(DeadReason::Revoked);
    // A heartbeat arriving after revocation must not resurrect the
    // session — explicit rejection ends access, period.
    state.on_heartbeat_ok(lease);
    assert!(matches!(
        state.authorize(now),
        Err(KeystoneError::Revoked)
    ));
}

/// The manifest's download_id is signed like every other attested
/// field — a captured manifest's download attribution can't be
/// rewritten without breaking the signature.
#[test]
fn manifest_download_id_is_signed() {
    let issuer = Issuer::generate();
    let now = Utc::now();
    let manifest = Manifest {
        product: "prod".into(),
        version: "1.0.0".into(),
        build_id: "build-a1b2c3".into(),
        download_id: "dl-9f8e7d".into(),
        sha256: [0u8; 32],
        feature_grants: vec![],
        issued_at: now,
        expires_at: now + Duration::minutes(5),
    };
    let mut signed = SignedManifest::issue(&issuer, manifest);
    signed
        .verify(&issuer.verifying_key(), now)
        .expect("fresh manifest must verify");

    signed.manifest.download_id = "dl-forged".into();
    assert!(matches!(
        signed.verify(&issuer.verifying_key(), now),
        Err(KeystoneError::InvalidSignature)
    ));
}

/// Debug output must never carry session material: envelope bodies
/// hold session keys, handoff ciphertext is opaque, and the handoff
/// payload's session_key is the secret the whole scheme protects.
#[test]
fn debug_impls_do_not_leak_secrets() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let out = format!("{env:?}");
    assert!(out.contains("[10 bytes]"), "body must print as a length");
    assert!(
        !out.contains("grant-body"),
        "envelope body leaked into Debug: {out}"
    );

    let payload = HandoffPayload {
        session_id: session,
        session_key: [0xAB; 32],
        lease: Lease {
            session_id: session,
            granted_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
            grace_period: Duration::seconds(60),
        },
        server_pubkey: [0x77; 32],
    };
    let key = [0x42; 32];
    let blob = Handoff::seal(&key, &payload, "game.exe", Duration::seconds(60)).unwrap();

    let out = format!("{payload:?}");
    assert!(out.contains("[redacted]"));
    assert!(
        !out.contains("171"),
        "session_key bytes leaked into Debug: {out}"
    );

    let out = format!("{blob:?}");
    assert!(out.contains("bytes]"), "ciphertext must print as a length");
    assert!(
        !out.contains(&format!("{:?}", blob.ciphertext)),
        "ciphertext leaked into Debug: {out}"
    );
}

/// AccountFile::save must round-trip through the temp-file rename and
/// leave no stray temp siblings behind.
#[test]
fn account_file_save_roundtrips() {
    let dir = std::env::temp_dir().join(format!("keystone-accounts-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("accounts.json");

    let file = AccountFile {
        accounts: vec![AccountRecord {
            name: "dev".into(),
            secret_hash: "$argon2id$v=19$fake".into(),
            entitlements: vec![AccountGrant {
                product: "prod".into(),
                expires_at: Utc::now() + Duration::days(30),
                features: vec!["a".into()],
            }],
            cert_sha256: None,
        }],
    };
    file.save(&path).expect("save");
    let loaded = AccountFile::load(&path).expect("load");
    assert_eq!(loaded.accounts.len(), 1);
    assert_eq!(loaded.accounts[0].name, "dev");
    assert_eq!(loaded.accounts[0].secret_hash, "$argon2id$v=19$fake");

    // A second save over the same path must also work — no fixed
    // .tmp name to collide with.
    file.save(&path).expect("second save");
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name() != "accounts.json")
        .collect();
    assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// The account record's secret_hash must never appear in Debug output.
#[test]
fn account_debug_redacts_secret_hash() {
    let file = AccountFile {
        accounts: vec![AccountRecord {
            name: "dev".into(),
            secret_hash: "$argon2id$v=19$supersecrethash".into(),
            entitlements: vec![],
            cert_sha256: None,
        }],
    };
    let out = format!("{file:?}");
    assert!(out.contains("[redacted]"));
    assert!(
        !out.contains("supersecrethash"),
        "secret_hash leaked into Debug: {out}"
    );
}

/// Same sweep as every_signed_field_is_actually_signed, for manifests:
/// every attested field — product, version, build_id, download_id,
/// sha256, feature_grants, issued_at, expires_at — must be inside the
/// signature. A field dropped from canonical_bytes would mutate
/// cleanly and still verify.
#[test]
fn every_manifest_field_is_actually_signed() {
    let issuer = Issuer::generate();
    let now = Utc::now();
    let key = issuer.verifying_key();
    let base = Manifest {
        product: "prod".into(),
        version: "1.0.0".into(),
        build_id: "build-a1b2c3".into(),
        download_id: "dl-9f8e7d".into(),
        sha256: [0x11u8; 32],
        feature_grants: vec![FeatureGrant {
            feature: "esp".into(),
            expires_at: now + Duration::days(30),
        }],
        issued_at: now,
        expires_at: now + Duration::minutes(5),
    };
    let signed = SignedManifest::issue(&issuer, base.clone());
    signed.verify(&key, now).expect("fresh manifest must verify");

    let mut m = signed.clone();
    m.manifest.product = "forged".into();
    assert!(matches!(
        m.verify(&key, now),
        Err(KeystoneError::InvalidSignature)
    ));

    let mut m = signed.clone();
    m.manifest.version = "9.9.9".into();
    assert!(matches!(
        m.verify(&key, now),
        Err(KeystoneError::InvalidSignature)
    ));

    let mut m = signed.clone();
    m.manifest.build_id = "build-forged".into();
    assert!(matches!(
        m.verify(&key, now),
        Err(KeystoneError::InvalidSignature)
    ));

    let mut m = signed.clone();
    m.manifest.download_id = "dl-forged".into();
    assert!(matches!(
        m.verify(&key, now),
        Err(KeystoneError::InvalidSignature)
    ));

    // The killer case: swapping in the hash of an attacker's payload.
    let mut m = signed.clone();
    m.manifest.sha256 = [0xEEu8; 32];
    assert!(matches!(
        m.verify(&key, now),
        Err(KeystoneError::InvalidSignature)
    ));

    // Grants: both the feature name and its expiry are signed.
    let mut m = signed.clone();
    m.manifest.feature_grants[0].feature = "fly".into();
    assert!(matches!(
        m.verify(&key, now),
        Err(KeystoneError::InvalidSignature)
    ));
    let mut m = signed.clone();
    m.manifest.feature_grants[0].expires_at = now + Duration::days(365);
    assert!(matches!(
        m.verify(&key, now),
        Err(KeystoneError::InvalidSignature)
    ));
    // Adding a grant post-signing changes the signed count too.
    let mut m = signed.clone();
    m.manifest.feature_grants.push(FeatureGrant {
        feature: "fly".into(),
        expires_at: now + Duration::days(30),
    });
    assert!(matches!(
        m.verify(&key, now),
        Err(KeystoneError::InvalidSignature)
    ));

    let mut m = signed.clone();
    m.manifest.issued_at = now - Duration::days(365);
    assert!(matches!(
        m.verify(&key, now),
        Err(KeystoneError::InvalidSignature)
    ));

    // Extending expiry on a dead manifest must not resurrect it.
    let mut m = signed;
    m.manifest.expires_at = now + Duration::days(365);
    assert!(matches!(
        m.verify(&key, now),
        Err(KeystoneError::InvalidSignature)
    ));
}

/// HKDF domain separation: keys and MACs derived for one purpose must
/// never verify as another — the domain byte strings are the whole
/// reason a captured wrap or MAC is dead material anywhere else.
#[test]
fn payload_key_domains_do_not_cross() {
    let ikm = b"shared-input-key-material";
    let salt = b"session-salt";
    let context = artifact_context("prod", "1.0.0");

    // Salt variation: a different salt derives a different key — the
    // per-session binding is real, not decorative.
    let key = derive_payload_key(ikm, salt, &context);
    assert_ne!(key, derive_payload_key(ikm, b"other-salt", &context));

    // Cross-domain: the payload key and the key-wrap key share HKDF
    // but different domain strings — same ikm+salt must diverge.
    let wrap = payload_wrap_key(&key, &[0x33u8; 32]);
    assert_ne!(
        key,
        derive_payload_key(ikm, salt, b"keystone.key-wrap.v1")
    );
    assert_ne!(wrap, key);

    // MAC domains: a heartbeat MAC must never verify as a response
    // MAC and vice versa, even over identical inputs.
    let session_key = [0x55u8; 32];
    let session_id = Uuid::new_v4();
    let nonce = [0x66u8; 32];
    let hb = mac_heartbeat(&session_key, &session_id, &nonce);
    assert!(matches!(
        verify_response_mac(&session_key, &nonce, &hb, &hb),
        Err(KeystoneError::InvalidMac)
    ));
    let resp = mac_response(&session_key, &nonce, b"heartbeat");
    assert!(matches!(
        verify_heartbeat_mac(&session_key, &session_id, &nonce, &resp),
        Err(KeystoneError::InvalidMac)
    ));
}
