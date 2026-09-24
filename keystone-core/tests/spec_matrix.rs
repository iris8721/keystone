//! The self-test matrix, executable: altered artifacts, expired grants,
//! wrong-product auth, reused one-time responses, revoked sessions, and
//! stale challenges must all be rejected.

use std::time::Instant;

use chrono::{DateTime, Duration, Utc};
use keystone_core::wire::{self, ErrorBody, ErrorCode, Verdict, mac_context};
use keystone_core::*;
use uuid::Uuid;
use zeroize::Zeroizing;

const AUDIENCE: &str = "keystone-server";
const OPERATION: &str = "payload.download";

fn setup() -> (Issuer, Challenge, Uuid) {
    (Issuer::generate(1), Challenge::new(), Uuid::new_v4())
}

fn trust_for(issuer: &Issuer) -> TrustedIssuers {
    TrustedIssuers::single(issuer.key_id(), issuer.verifying_key())
}

fn issue_at(
    issuer: &Issuer,
    challenge: &Challenge,
    session: Uuid,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Envelope {
    Envelope::issue(
        issuer,
        IssueSpec {
            challenge: challenge.nonce,
            session_id: session,
            audience: AUDIENCE.to_string(),
            operation: OPERATION.to_string(),
            issued_at,
            expires_at,
            body: b"grant-body".to_vec(),
        },
    )
}

fn issue_valid(issuer: &Issuer, challenge: &Challenge, session: Uuid) -> Envelope {
    let now = Utc::now();
    issue_at(issuer, challenge, session, now, now + Duration::seconds(60))
}

fn expect_for<'a>(
    challenge: &'a Challenge,
    session: &'a Uuid,
    now: DateTime<Utc>,
) -> Expectation<'a> {
    Expectation {
        challenge,
        session_id: session,
        audience: AUDIENCE,
        operation: OPERATION,
        now,
    }
}

fn bootstrap_for<'a>(challenge: &'a Challenge, session: &'a Uuid) -> BootstrapExpectation<'a> {
    BootstrapExpectation {
        challenge,
        session_id: session,
        audience: AUDIENCE,
        operation: OPERATION,
    }
}

fn minted_ago(secs: u64) -> Challenge {
    Challenge {
        minted: Instant::now()
            .checked_sub(std::time::Duration::from_secs(secs))
            .expect("monotonic clock has run longer than the test offset"),
        ..Challenge::new()
    }
}

fn lease(now: DateTime<Utc>, ttl: Duration, grace: Duration) -> Lease {
    Lease {
        session_id: Uuid::new_v4(),
        granted_at: now,
        expires_at: now + ttl,
        grace_period: grace,
    }
}

fn manifest_for(now: DateTime<Utc>) -> Manifest {
    Manifest {
        product: "prod".into(),
        version: "1.0.0".into(),
        build_id: "build-a1b2c3".into(),
        download_id: "dl-9f8e7d".into(),
        sha256: [0x11u8; 32],
        issued_at: now,
        expires_at: now + Duration::minutes(5),
    }
}

#[test]
fn valid_envelope_verifies() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    env.verify(
        &trust_for(&issuer),
        &expect_for(&challenge, &session, Utc::now()),
    )
    .expect("valid envelope must verify");
}

#[test]
fn altered_body_rejected() {
    let (issuer, challenge, session) = setup();
    let mut env = issue_valid(&issuer, &challenge, session);
    env.body = b"forged-body".to_vec();
    assert!(matches!(
        env.verify(
            &trust_for(&issuer),
            &expect_for(&challenge, &session, Utc::now())
        ),
        Err(KeystoneError::InvalidSignature)
    ));
}

#[test]
fn replayed_old_response_rejected() {
    let (issuer, old_challenge, session) = setup();
    let env = issue_valid(&issuer, &old_challenge, session);
    let new_challenge = Challenge::new();
    assert!(matches!(
        env.verify(
            &trust_for(&issuer),
            &expect_for(&new_challenge, &session, Utc::now())
        ),
        Err(KeystoneError::ChallengeMismatch)
    ));
}

#[test]
fn expired_challenge_rejected_by_verify() {
    // The echo matches and the envelope is in date; only the challenge's
    // monotonic age is wrong.
    let issuer = Issuer::generate(1);
    let session = Uuid::new_v4();
    let stale = minted_ago(Challenge::TTL.as_secs() + 1);
    let env = issue_valid(&issuer, &stale, session);
    assert!(matches!(
        env.verify(
            &trust_for(&issuer),
            &expect_for(&stale, &session, Utc::now())
        ),
        Err(KeystoneError::Stale)
    ));
    assert!(matches!(
        env.verify_bootstrap(&trust_for(&issuer), &bootstrap_for(&stale, &session)),
        Err(KeystoneError::Stale)
    ));

    let fresh = minted_ago(Challenge::TTL.as_secs() - 5);
    let env = issue_valid(&issuer, &fresh, session);
    env.verify(
        &trust_for(&issuer),
        &expect_for(&fresh, &session, Utc::now()),
    )
    .expect("a challenge inside its window verifies");
}

#[test]
fn verify_bootstrap_accepts_server_ahead_and_returns_drift() {
    let (issuer, challenge, session) = setup();
    let server_now = Utc::now() + Duration::minutes(10);
    let env = issue_at(
        &issuer,
        &challenge,
        session,
        server_now,
        server_now + Duration::minutes(5),
    );

    // The session-bound check refuses a grant from ten minutes ahead.
    assert!(matches!(
        env.verify(
            &trust_for(&issuer),
            &expect_for(&challenge, &session, Utc::now())
        ),
        Err(KeystoneError::ClockSkew)
    ));

    let drift = env
        .verify_bootstrap(&trust_for(&issuer), &bootstrap_for(&challenge, &session))
        .expect("bootstrap tolerates a skewed server clock");
    assert!(
        (drift - Duration::minutes(10)).num_seconds().abs() < 5,
        "drift {drift} should be about ten minutes"
    );
}

#[test]
fn verify_bootstrap_counts_the_round_trip_against_expiry() {
    // The response may have been issued as early as the challenge was
    // minted, so it is up to rtt old on the server's clock. A 50 s round
    // trip leaves nothing of a 30 s grant.
    let issuer = Issuer::generate(1);
    let session = Uuid::new_v4();
    let challenge = minted_ago(50);
    let now = Utc::now();
    let short = issue_at(
        &issuer,
        &challenge,
        session,
        now,
        now + Duration::seconds(30),
    );
    assert!(matches!(
        short.verify_bootstrap(&trust_for(&issuer), &bootstrap_for(&challenge, &session)),
        Err(KeystoneError::Expired)
    ));

    // With enough lifetime left it is accepted, and the drift estimate
    // takes the midpoint of the round trip.
    let long = issue_at(
        &issuer,
        &challenge,
        session,
        now,
        now + Duration::minutes(5),
    );
    let drift = long
        .verify_bootstrap(&trust_for(&issuer), &bootstrap_for(&challenge, &session))
        .unwrap();
    assert!(
        (drift - Duration::seconds(25)).num_seconds().abs() < 3,
        "drift {drift} should be about half the round trip"
    );
}

#[test]
fn download_authorization_round_trips_and_rejects_deviations() {
    let auth = wire::DownloadAuthorization {
        session_id: Uuid::new_v4(),
        nonce: [0xA1; 32],
        issued_at: DateTime::from_timestamp_millis(1_900_000_000_123).unwrap(),
        mac: [0x5C; 32],
    };
    let header = auth.encode();
    assert_eq!(
        header,
        format!(
            "Keystone {}:{}:1900000000123:{}",
            auth.session_id,
            "a1".repeat(32),
            "5c".repeat(32)
        )
    );
    assert_eq!(wire::DownloadAuthorization::parse(&header).unwrap(), auth);

    let fields: Vec<&str> = header["Keystone ".len()..].split(':').collect();
    let variants = [
        header.replacen("Keystone ", "Bearer ", 1),
        header.replacen("Keystone ", "keystone ", 1),
        format!("{header}:extra"),
        fields[..3].join(":"),
        format!(
            "Keystone not-a-uuid:{}:{}:{}",
            fields[1], fields[2], fields[3]
        ),
        format!(
            "Keystone {}:{}:{}:{}",
            fields[0],
            &fields[1][2..],
            fields[2],
            fields[3]
        ),
        format!("Keystone {}:{}:1.5:{}", fields[0], fields[1], fields[3]),
        format!(
            "Keystone {}:{}:{}:{}zz",
            fields[0],
            fields[1],
            fields[2],
            &fields[3][2..]
        ),
    ];
    for bad in variants {
        assert!(
            matches!(
                wire::DownloadAuthorization::parse(&bad),
                Err(KeystoneError::Malformed(_))
            ),
            "{bad:?} accepted"
        );
    }
}

#[test]
fn build_ids_are_bounded_safe_tokens() {
    wire::validate_build_id("build-2030.01_a1b2").unwrap();
    wire::validate_build_id(&"b".repeat(wire::MAX_BUILD_ID_LEN)).unwrap();
    assert!(matches!(
        wire::validate_build_id(&"b".repeat(wire::MAX_BUILD_ID_LEN + 1)),
        Err(KeystoneError::FieldTooLong("build_id"))
    ));
    for bad in [
        "",
        "a b",
        "a/b",
        "a:b",
        "line\nbreak",
        "caf\u{e9}",
        "sha256:ab",
    ] {
        assert!(
            matches!(
                wire::validate_build_id(bad),
                Err(KeystoneError::Malformed(_))
            ),
            "{bad:?} accepted"
        );
    }
}

#[test]
fn release_paths_come_only_from_valid_segments() {
    wire::validate_release("prod", "1.0.0").unwrap();
    assert_eq!(
        wire::paths::download("prod", "1.0.0"),
        "/payload/prod/1.0.0"
    );
    for (product, version) in [
        ("CON", "1.0"),
        ("prod", "nul.txt"),
        ("prod", "1.0."),
        ("", "1"),
    ] {
        assert!(
            matches!(
                wire::validate_release(product, version),
                Err(KeystoneError::Malformed(_))
            ),
            "{product:?}/{version:?} accepted"
        );
    }
    assert!(matches!(
        wire::validate_release("prod", &"9".repeat(wire::MAX_VERSION_LEN + 1)),
        Err(KeystoneError::FieldTooLong("version"))
    ));
}

#[test]
fn verify_bootstrap_judges_expiry_on_the_server_clock() {
    let (issuer, challenge, session) = setup();
    let trusted = trust_for(&issuer);

    // Server ten minutes behind: already expired on local time, alive on
    // the server's.
    let server_now = Utc::now() - Duration::minutes(10);
    let behind = issue_at(
        &issuer,
        &challenge,
        session,
        server_now,
        server_now + Duration::minutes(5),
    );
    assert!(matches!(
        behind.verify(&trusted, &expect_for(&challenge, &session, Utc::now())),
        Err(KeystoneError::Expired)
    ));
    let drift = behind
        .verify_bootstrap(&trusted, &bootstrap_for(&challenge, &session))
        .unwrap();
    assert!(drift < -Duration::minutes(9));

    // Dead at issue on the server's own clock.
    let server_now = Utc::now() + Duration::minutes(10);
    let dead = issue_at(&issuer, &challenge, session, server_now, server_now);
    assert!(matches!(
        dead.verify_bootstrap(&trusted, &bootstrap_for(&challenge, &session)),
        Err(KeystoneError::Expired)
    ));
}

#[test]
fn verify_bootstrap_checks_every_binding() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let trusted = trust_for(&issuer);

    let other = Challenge::new();
    assert!(matches!(
        env.verify_bootstrap(&trusted, &bootstrap_for(&other, &session)),
        Err(KeystoneError::ChallengeMismatch)
    ));
    let other_session = Uuid::new_v4();
    assert!(matches!(
        env.verify_bootstrap(&trusted, &bootstrap_for(&challenge, &other_session)),
        Err(KeystoneError::SessionMismatch)
    ));
    let mut expect = bootstrap_for(&challenge, &session);
    expect.operation = "session.exchange";
    assert!(matches!(
        env.verify_bootstrap(&trusted, &expect),
        Err(KeystoneError::OperationMismatch { .. })
    ));
    let mut forged = env.clone();
    forged.issued_at -= Duration::milliseconds(1);
    assert!(matches!(
        forged.verify_bootstrap(&trusted, &bootstrap_for(&challenge, &session)),
        Err(KeystoneError::InvalidSignature)
    ));
}

#[test]
fn replayed_accepted_response_rejected() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let now = Utc::now();
    env.verify(&trust_for(&issuer), &expect_for(&challenge, &session, now))
        .unwrap();

    let mut consumed = ConsumedSet::new();
    consumed
        .consume(challenge.nonce, env.expires_at, now)
        .unwrap();
    assert!(matches!(
        consumed.consume(challenge.nonce, env.expires_at, now),
        Err(KeystoneError::AlreadyConsumed)
    ));
}

#[test]
fn consume_rejects_nonce_at_its_expiry() {
    let mut set = ConsumedSet::new();
    let t = Utc::now();
    // At the boundary the value is already dead: refusing it is the only
    // answer that agrees with eviction.
    assert!(matches!(
        set.consume([1u8; 32], t, t),
        Err(KeystoneError::Stale)
    ));
    assert!(matches!(
        set.consume([1u8; 32], t - Duration::milliseconds(1), t),
        Err(KeystoneError::Stale)
    ));
    assert!(set.is_empty());

    // No gap: an entry is held while acceptable, and refused once evictable.
    let expiry = t + Duration::milliseconds(1);
    set.consume([2u8; 32], expiry, t).unwrap();
    set.evict_expired(t);
    assert!(matches!(
        set.consume([2u8; 32], expiry, t),
        Err(KeystoneError::AlreadyConsumed)
    ));
    set.evict_expired(expiry);
    assert!(!set.is_consumed(&[2u8; 32]));
    assert!(matches!(
        set.consume([2u8; 32], expiry, expiry),
        Err(KeystoneError::Stale)
    ));
}

#[test]
fn consumed_set_evicts_only_dead_entries() {
    let mut set = ConsumedSet::new();
    let now = Utc::now();
    set.consume([1u8; 32], now + Duration::seconds(10), now)
        .unwrap();
    set.consume([2u8; 32], now + Duration::seconds(1), now)
        .unwrap();
    set.evict_expired(now + Duration::seconds(1));
    assert_eq!(set.len(), 1);
    assert!(set.is_consumed(&[1u8; 32]));
    assert!(!set.is_consumed(&[2u8; 32]));
}

#[test]
fn expired_envelope_rejected() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let trusted = trust_for(&issuer);
    assert!(matches!(
        env.verify(
            &trusted,
            &expect_for(&challenge, &session, env.expires_at + Duration::seconds(1))
        ),
        Err(KeystoneError::Expired)
    ));
    assert!(matches!(
        env.verify(&trusted, &expect_for(&challenge, &session, env.expires_at)),
        Err(KeystoneError::Expired)
    ));
    env.verify(
        &trusted,
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
    let mut expect = expect_for(&challenge, &session, Utc::now());
    expect.audience = "some-other-service";
    assert!(matches!(
        env.verify(&trust_for(&issuer), &expect),
        Err(KeystoneError::AudienceMismatch { .. })
    ));
}

#[test]
fn wrong_operation_rejected() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let mut expect = expect_for(&challenge, &session, Utc::now());
    expect.operation = "feature.esp";
    assert!(matches!(
        env.verify(&trust_for(&issuer), &expect),
        Err(KeystoneError::OperationMismatch { .. })
    ));
}

#[test]
fn wrong_session_rejected() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let other_session = Uuid::new_v4();
    assert!(matches!(
        env.verify(
            &trust_for(&issuer),
            &expect_for(&challenge, &other_session, Utc::now())
        ),
        Err(KeystoneError::SessionMismatch)
    ));
}

#[test]
fn wrong_issuer_key_rejected() {
    // Same key id, different key.
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let attacker = Issuer::generate(issuer.key_id());
    assert!(matches!(
        env.verify(
            &trust_for(&attacker),
            &expect_for(&challenge, &session, Utc::now())
        ),
        Err(KeystoneError::InvalidSignature)
    ));
}

#[test]
fn request_mac_binds_session_nonce_time_and_operation() {
    let session_key = b"session-secret-material";
    let session_id = Uuid::new_v4();
    let other_session = Uuid::new_v4();
    let nonce = [7u8; 32];
    let other_nonce = [9u8; 32];
    let heartbeat = mac_context::heartbeat();
    let at = Utc::now();
    let bind = RequestBinding {
        session_id: &session_id,
        nonce: &nonce,
        issued_at: at,
        context: &heartbeat,
    };
    let mac = mac_request(session_key, &bind);
    verify_request_mac(session_key, &bind, &mac).unwrap();

    let attest = mac_context::attest(&[1u8; 32], "game.exe");
    let rebinds = [
        RequestBinding {
            nonce: &other_nonce,
            ..bind
        },
        RequestBinding {
            session_id: &other_session,
            ..bind
        },
        RequestBinding {
            issued_at: at + Duration::milliseconds(1),
            ..bind
        },
        RequestBinding {
            context: &attest,
            ..bind
        },
    ];
    for bad in &rebinds {
        assert!(matches!(
            verify_request_mac(session_key, bad, &mac),
            Err(KeystoneError::InvalidMac)
        ));
    }
    assert!(matches!(
        verify_request_mac(b"other-session", &bind, &mac),
        Err(KeystoneError::InvalidMac)
    ));
}

#[test]
fn mac_contexts_bind_their_arguments() {
    assert_ne!(
        mac_context::payload("a", "bc"),
        mac_context::payload("ab", "c")
    );
    assert_ne!(
        mac_context::payload("p", "1"),
        mac_context::download("p", "1")
    );
    assert_ne!(
        mac_context::handoff("game.exe", 60_000),
        mac_context::handoff("game.exe", 60_001)
    );
    assert_ne!(
        mac_context::handoff("game.exe", 1),
        mac_context::handoff("other.exe", 1)
    );
    assert_ne!(
        mac_context::attest(&[1u8; 32], "game.exe"),
        mac_context::attest(&[2u8; 32], "game.exe")
    );
    assert_ne!(
        mac_context::attest(&[1u8; 32], "game.exe"),
        mac_context::attest(&[1u8; 32], "other.exe")
    );
}

#[test]
fn wire_timestamps_are_integer_millis() {
    // Sub-millisecond digits exist in memory but have no wire form, so they
    // can neither be signed nor smuggled past a signature.
    let (issuer, challenge, session) = setup();
    let issued_at = DateTime::from_timestamp(1_900_000_000, 123_456_789).unwrap();
    let env = issue_at(
        &issuer,
        &challenge,
        session,
        issued_at,
        issued_at + Duration::seconds(60),
    );
    let json = serde_json::to_value(&env).unwrap();
    assert_eq!(json["issued_at"], serde_json::json!(1_900_000_000_123i64));

    let back: Envelope = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(back.issued_at.timestamp_subsec_nanos(), 123_000_000);
    back.verify(
        &trust_for(&issuer),
        &expect_for(&challenge, &session, issued_at),
    )
    .expect("the ms-aligned wire value carries the signature");

    for smuggled in [
        serde_json::json!(1_900_000_000_123.9f64),
        serde_json::json!("2030-03-17T17:46:40.123999Z"),
    ] {
        let mut tampered = json.clone();
        tampered["expires_at"] = smuggled;
        assert!(serde_json::from_value::<Envelope>(tampered).is_err());
    }

    // Requests: the MAC the client computed over a nanosecond clock
    // verifies against the value the server deserializes.
    let session_key = [5u8; 32];
    let nonce = [6u8; 32];
    let context = mac_context::heartbeat();
    let minted = RequestBinding {
        session_id: &session,
        nonce: &nonce,
        issued_at,
        context: &context,
    };
    let req = wire::HeartbeatRequest {
        session_id: session,
        nonce,
        issued_at,
        mac: mac_request(&session_key, &minted),
    };
    let received: wire::HeartbeatRequest =
        serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
    assert_eq!(received.issued_at.timestamp_subsec_nanos() % 1_000_000, 0);
    verify_request_mac(
        &session_key,
        &RequestBinding {
            issued_at: received.issued_at,
            ..minted
        },
        &received.mac,
    )
    .unwrap();
}

#[test]
fn error_code_unknown_strings_fall_back() {
    let code: ErrorCode = serde_json::from_str("\"quota_exceeded_v9\"").unwrap();
    assert_eq!(code, ErrorCode::Unknown);
    assert_eq!(code.verdict(), Verdict::Transient);

    let body: ErrorBody =
        serde_json::from_str(r#"{"code":"not_a_code","message":"later server"}"#).unwrap();
    assert_eq!(body.code, ErrorCode::Unknown);
    assert!(serde_json::from_str::<ErrorCode>("7").is_err());
}

#[test]
fn error_code_wire_strings_and_verdicts() {
    use DeadReason::*;
    use ErrorCode as C;
    let table = [
        (
            C::InvalidCredentials,
            "invalid_credentials",
            Verdict::RequestError,
        ),
        (C::InvalidMac, "invalid_mac", Verdict::Kill(Rejected)),
        (C::StaleRequest, "stale_request", Verdict::Transient),
        (C::Replay, "replay", Verdict::Transient),
        (C::RateLimited, "rate_limited", Verdict::Transient),
        (
            C::UnknownSession,
            "unknown_session",
            Verdict::Kill(UnknownSession),
        ),
        (C::SessionRevoked, "session_revoked", Verdict::Kill(Revoked)),
        (C::SessionExpired, "session_expired", Verdict::Kill(Expired)),
        (
            C::GraceExhausted,
            "grace_exhausted",
            Verdict::Kill(GraceExhausted),
        ),
        (C::NoEntitlement, "no_entitlement", Verdict::Kill(Revoked)),
        (C::WrongProduct, "wrong_product", Verdict::RequestError),
        (C::HandoffInvalid, "handoff_invalid", Verdict::RequestError),
        (
            C::ArtifactNotFound,
            "artifact_not_found",
            Verdict::Transient,
        ),
        (
            C::ArtifactInvalid,
            "artifact_invalid",
            Verdict::RequestError,
        ),
        (
            C::BackendUnavailable,
            "backend_unavailable",
            Verdict::Transient,
        ),
        (
            C::UnsupportedProtocol,
            "unsupported_protocol",
            Verdict::RequestError,
        ),
        (C::BadRequest, "bad_request", Verdict::RequestError),
        (C::Forbidden, "forbidden", Verdict::RequestError),
        (
            C::ActiveSigningKey,
            "active_signing_key",
            Verdict::RequestError,
        ),
        (C::Conflict, "conflict", Verdict::RequestError),
        (C::Unknown, "unknown", Verdict::Transient),
    ];
    for (code, wire_str, verdict) in table {
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, format!("\"{wire_str}\""));
        assert_eq!(serde_json::from_str::<ErrorCode>(&json).unwrap(), code);
        assert_eq!(code.verdict(), verdict, "{wire_str}");
    }
}

#[test]
fn revoke_target_is_externally_tagged_snake_case() {
    let session = Uuid::new_v4();
    let cases = [
        (
            wire::RevokeTarget::Session(session),
            serde_json::json!({ "session": session }),
        ),
        (
            wire::RevokeTarget::Account("dev".into()),
            serde_json::json!({ "account": "dev" }),
        ),
        (
            wire::RevokeTarget::KeyId(3),
            serde_json::json!({ "key_id": 3 }),
        ),
    ];
    for (target, json) in cases {
        assert_eq!(serde_json::to_value(&target).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<wire::RevokeTarget>(json).unwrap(),
            target
        );
    }
}

#[test]
fn request_validation_enforces_caps() {
    let exchange = |account: &str, product: &str| wire::ExchangeRequest {
        account: account.into(),
        secret: Zeroizing::new("s3cret".into()),
        product: product.into(),
        hwid: [0; 32],
        challenge: [0; 32],
    };
    exchange(&"a".repeat(wire::MAX_ACCOUNT_LEN), "prod")
        .validate()
        .unwrap();
    assert!(matches!(
        exchange(&"a".repeat(wire::MAX_ACCOUNT_LEN + 1), "prod").validate(),
        Err(KeystoneError::FieldTooLong("account"))
    ));
    assert!(matches!(
        exchange("dev", &"p".repeat(wire::MAX_PRODUCT_LEN + 1)).validate(),
        Err(KeystoneError::FieldTooLong("product"))
    ));
    assert!(matches!(
        exchange("", "prod").validate(),
        Err(KeystoneError::Malformed(_))
    ));

    let payload = |product: &str, version: &str| wire::PayloadRequest {
        session_id: Uuid::nil(),
        product: product.into(),
        version: version.into(),
        nonce: [0; 32],
        issued_at: Utc::now(),
        mac: [0; 32],
    };
    payload("prod", "1.0").validate().unwrap();
    for (product, version) in [("..", "1.0"), ("prod", "../1.0"), ("prod", "a/b")] {
        assert!(matches!(
            payload(product, version).validate(),
            Err(KeystoneError::Malformed(_))
        ));
    }

    let handoff = |process_id: &str, ttl_millis: u64| wire::HandoffRequest {
        session_id: Uuid::nil(),
        nonce: [0; 32],
        issued_at: Utc::now(),
        process_id: process_id.into(),
        ttl_millis,
        mac: [0; 32],
    };
    assert!(matches!(
        handoff(&"x".repeat(wire::MAX_PROCESS_ID_LEN + 1), 1).validate(),
        Err(KeystoneError::FieldTooLong("process_id"))
    ));
    assert!(handoff("game.exe", 0).validate().is_err());
    assert_eq!(handoff("game.exe", u64::MAX).ttl(), wire::MAX_HANDOFF_TTL);
}

#[test]
fn artifact_key_requires_the_secret_and_the_release() {
    let secret = [0x21u8; 32];
    let context = artifact_context("aimbot", "1.4.2", 0);
    let sealed = seal_artifact(&secret, &context, b"payload").unwrap();
    let prefix: &[u8; SEALED_PREFIX_LEN] = sealed[..SEALED_PREFIX_LEN].try_into().unwrap();

    let right = artifact_key_from_prefix(&secret, &context, prefix);
    assert_eq!(
        decrypt_artifact(&right, &sealed).unwrap().as_slice(),
        b"payload"
    );
    for wrong in [
        artifact_key_from_prefix(&[0x22u8; 32], &context, prefix),
        artifact_key_from_prefix(&secret, &artifact_context("esp", "1.4.2", 0), prefix),
        artifact_key_from_prefix(&secret, &artifact_context("aimbot", "1.4.3", 0), prefix),
    ] {
        assert!(matches!(
            decrypt_artifact(&wrong, &sealed),
            Err(KeystoneError::InvalidMac)
        ));
    }
}

#[test]
fn wrap_key_domains_do_not_cross() {
    // The same secret and salt must yield different wrap keys per purpose,
    // so a payload wrap never opens as a child session key and vice versa.
    let secret = [0x33u8; 32];
    let salt = [0x44u8; 32];
    let payload_wrap = payload_wrap_key(&secret, &salt);
    let handoff_wrap = handoff_wrap_key(&secret, &salt);
    assert_ne!(payload_wrap, handoff_wrap);

    let wrap = wrap_secret(&payload_wrap, &[0x55u8; 32]);
    assert_eq!(*unwrap_secret(&payload_wrap, &wrap).unwrap(), [0x55u8; 32]);
    assert!(matches!(
        unwrap_secret(&handoff_wrap, &wrap),
        Err(KeystoneError::InvalidMac)
    ));
    assert_eq!(
        *unwrap_artifact_key(&secret, &salt, &wrap).unwrap(),
        [0x55u8; 32]
    );
}

#[test]
fn request_freshness_window_is_symmetric_and_inclusive() {
    let now = Utc::now();
    check_request_freshness(now - REQUEST_SKEW, now).unwrap();
    check_request_freshness(now + REQUEST_SKEW, now).unwrap();
    assert!(matches!(
        check_request_freshness(now - REQUEST_SKEW - Duration::milliseconds(1), now),
        Err(KeystoneError::ClockSkew)
    ));
    assert!(matches!(
        check_request_freshness(now + REQUEST_SKEW + Duration::milliseconds(1), now),
        Err(KeystoneError::ClockSkew)
    ));
}

#[test]
fn request_nonce_is_held_for_the_whole_freshness_window() {
    // While the timestamp still passes freshness, the nonce must still be
    // consumable exactly once; after that the timestamp alone rejects it.
    let at = Utc::now();
    let expiry = request_nonce_expiry(at);
    let mut set = ConsumedSet::new();
    let last_fresh = expiry - Duration::milliseconds(1);
    check_request_freshness(at, last_fresh).unwrap();
    set.consume([1u8; 32], expiry, last_fresh).unwrap();
    set.evict_expired(last_fresh);
    assert!(matches!(
        set.consume([1u8; 32], expiry, last_fresh),
        Err(KeystoneError::AlreadyConsumed)
    ));
    assert!(matches!(
        check_request_freshness(at, expiry + Duration::milliseconds(1)),
        Err(KeystoneError::ClockSkew)
    ));
}

#[test]
fn grace_deadline_is_fixed() {
    let now = Utc::now();
    let mut state = SessionState::Active {
        lease: lease(now, Duration::minutes(10), Duration::minutes(2)),
    };
    state.on_transient_failure(now);
    assert!(state.authorize(now + Duration::seconds(60)).is_ok());
    state.on_transient_failure(now + Duration::seconds(90));
    assert!(matches!(
        state.authorize(now + Duration::seconds(121)),
        Err(KeystoneError::GraceExhausted)
    ));
}

#[test]
fn heartbeat_success_clears_grace() {
    let now = Utc::now();
    let first = lease(now, Duration::minutes(10), Duration::minutes(2));
    let mut state = SessionState::Active {
        lease: first.clone(),
    };
    state.on_transient_failure(now);
    let renewed = Lease {
        granted_at: now + Duration::seconds(30),
        ..first
    };
    state.on_heartbeat_ok(renewed, now + Duration::seconds(30));

    // A new failure starts a fresh window: probe past the old deadline.
    state.on_transient_failure(now + Duration::seconds(60));
    assert!(state.authorize(now + Duration::seconds(121)).is_ok());
    assert!(matches!(
        state.authorize(now + Duration::seconds(181)),
        Err(KeystoneError::GraceExhausted)
    ));
}

#[test]
fn dead_reasons_surface_as_their_own_errors() {
    let now = Utc::now();
    for (reason, check) in [
        (
            DeadReason::Rejected,
            (|e| matches!(e, KeystoneError::Rejected)) as fn(&KeystoneError) -> bool,
        ),
        (DeadReason::Revoked, |e| matches!(e, KeystoneError::Revoked)),
        (DeadReason::UnknownSession, |e| {
            matches!(e, KeystoneError::UnknownSession)
        }),
        (DeadReason::Expired, |e| matches!(e, KeystoneError::Expired)),
        (DeadReason::GraceExhausted, |e| {
            matches!(e, KeystoneError::GraceExhausted)
        }),
    ] {
        let mut state = SessionState::Active {
            lease: lease(now, Duration::minutes(10), Duration::minutes(2)),
        };
        state.kill(reason);
        let err = state.authorize(now).unwrap_err();
        assert!(check(&err), "{reason:?} surfaced as {err:?}");
    }
}

#[test]
fn lease_grace_period_is_integer_millis_on_the_wire() {
    let now = Utc::now();
    let l = lease(
        now,
        Duration::minutes(5),
        Duration::seconds(60) + Duration::nanoseconds(1_500_000),
    );
    let json = serde_json::to_value(&l).unwrap();
    assert_eq!(json["grace_period"], serde_json::json!(60_001i64));

    let back: Lease = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(back.grace_period, Duration::milliseconds(60_001));

    for smuggled in [serde_json::json!(60_001.5f64), serde_json::json!([60, 0])] {
        let mut tampered = json.clone();
        tampered["grace_period"] = smuggled;
        assert!(serde_json::from_value::<Lease>(tampered).is_err());
    }
}

#[test]
fn lease_expired_at_expiry() {
    let now = Utc::now();
    let l = lease(now, Duration::seconds(60), Duration::seconds(30));
    assert!(!l.is_expired(l.expires_at - Duration::milliseconds(1)));
    assert!(l.is_expired(l.expires_at));
}

#[test]
fn every_signed_field_is_actually_signed() {
    let (issuer, challenge, session) = setup();
    let base = issue_valid(&issuer, &challenge, session);
    let now = Utc::now();
    let key = trust_for(&issuer);

    let mutations: [fn(&mut Envelope); 7] = [
        |e| e.challenge = [0xAA; 32],
        |e| e.session_id = Uuid::new_v4(),
        |e| e.audience = "forged".into(),
        |e| e.operation = "forged".into(),
        |e| e.expires_at += Duration::days(365),
        |e| e.issued_at -= Duration::days(365),
        |e| e.body = b"forged".to_vec(),
    ];
    for mutate in mutations {
        let mut e = base.clone();
        mutate(&mut e);
        assert!(matches!(
            e.verify(&key, &expect_for(&challenge, &session, now)),
            Err(KeystoneError::InvalidSignature)
        ));
    }
}

#[test]
fn every_manifest_field_is_actually_signed() {
    let issuer = Issuer::generate(1);
    let now = Utc::now();
    let key = trust_for(&issuer);
    let signed = SignedManifest::issue(&issuer, manifest_for(now));
    signed
        .verify(&key, now)
        .expect("fresh manifest must verify");

    let mutations: [fn(&mut Manifest); 7] = [
        |m| m.product = "forged".into(),
        |m| m.version = "9.9.9".into(),
        |m| m.build_id = "build-forged".into(),
        |m| m.download_id = "dl-forged".into(),
        |m| m.sha256 = [0xEE; 32],
        |m| m.issued_at -= Duration::days(365),
        |m| m.expires_at += Duration::days(365),
    ];
    for mutate in mutations {
        let mut m = signed.clone();
        mutate(&mut m.manifest);
        assert!(matches!(
            m.verify(&key, now),
            Err(KeystoneError::InvalidSignature)
        ));
    }
}

#[test]
fn envelope_survives_json_roundtrip() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let now = Utc::now();
    let back: Envelope = serde_json::from_slice(&serde_json::to_vec(&env).unwrap()).unwrap();
    back.verify(&trust_for(&issuer), &expect_for(&challenge, &session, now))
        .expect("round-tripped envelope must still verify");

    // A string mutation keeps the JSON parseable, so only the signature
    // can catch it.
    let mut tampered = serde_json::to_value(&env).unwrap();
    tampered["audience"] = serde_json::json!("keystone-servfr");
    let e: Envelope = serde_json::from_value(tampered).unwrap();
    assert!(matches!(
        e.verify(&trust_for(&issuer), &expect_for(&challenge, &session, now)),
        Err(KeystoneError::InvalidSignature)
    ));
}

#[test]
fn accept_once_pipeline() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let now = Utc::now();
    let key = trust_for(&issuer);
    let mut consumed = ConsumedSet::new();

    env.verify(&key, &expect_for(&challenge, &session, now))
        .unwrap();
    consumed
        .consume(challenge.nonce, env.expires_at, now)
        .unwrap();

    // Replay: the signature is still valid, but the nonce is spent.
    env.verify(&key, &expect_for(&challenge, &session, now))
        .unwrap();
    assert!(matches!(
        consumed.consume(challenge.nonce, env.expires_at, now),
        Err(KeystoneError::AlreadyConsumed)
    ));
}

#[test]
fn lease_expiry_during_grace_is_expired_not_grace() {
    let now = Utc::now();
    let mut state = SessionState::Active {
        lease: lease(now, Duration::seconds(30), Duration::minutes(5)),
    };
    state.on_transient_failure(now);
    assert!(matches!(
        state.authorize(now + Duration::seconds(31)),
        Err(KeystoneError::Expired)
    ));
}

#[test]
fn dead_state_stays_dead() {
    let now = Utc::now();
    let l = lease(now, Duration::minutes(10), Duration::minutes(2));
    let mut state = SessionState::Active { lease: l.clone() };
    state.kill(DeadReason::Revoked);
    state.on_heartbeat_ok(l, now);
    assert!(matches!(state.authorize(now), Err(KeystoneError::Revoked)));
}

#[test]
fn late_heartbeat_after_grace_deadline_does_not_resurrect() {
    let now = Utc::now();
    let l = lease(now, Duration::minutes(10), Duration::minutes(2));
    let mut state = SessionState::Active { lease: l.clone() };
    state.on_transient_failure(now);

    let late = now + Duration::minutes(2) + Duration::seconds(1);
    state.on_heartbeat_ok(l, late);
    assert!(matches!(
        state,
        SessionState::Dead {
            reason: DeadReason::GraceExhausted
        }
    ));
    state.on_heartbeat_ok(
        lease(late, Duration::minutes(10), Duration::minutes(2)),
        late + Duration::seconds(1),
    );
    assert!(matches!(state, SessionState::Dead { .. }));
}

#[test]
fn debug_impls_do_not_leak_secrets() {
    let (issuer, challenge, session) = setup();
    let env = issue_valid(&issuer, &challenge, session);
    let out = format!("{env:?}");
    assert!(!out.contains("grant-body"), "envelope body leaked: {out}");

    let secret_bytes = format!("{:?}", [0xABu8; 32]);
    let payload = HandoffPayload {
        parent_session_id: session,
        handoff_id: [0x11; 32],
        handoff_secret: [0xAB; 32],
        product: "prod".into(),
        expires_at: Utc::now() + Duration::seconds(60),
        server_offset_millis: 0,
    };
    assert!(!format!("{payload:?}").contains(&secret_bytes));

    let exchange_body = wire::ExchangeBody {
        session_id: session,
        session_key: Zeroizing::new([0xAB; 32]),
        lease: lease(Utc::now(), Duration::minutes(5), Duration::minutes(1)),
        features: vec![],
        server_time: Utc::now(),
        revoked_key_ids: vec![],
    };
    assert!(!format!("{exchange_body:?}").contains(&secret_bytes));

    let handoff_body = wire::HandoffBody {
        handoff_id: [0x11; 32],
        handoff_secret: Zeroizing::new([0xAB; 32]),
        expires_at: Utc::now(),
        server_time: Utc::now(),
        revoked_key_ids: vec![],
    };
    assert!(!format!("{handoff_body:?}").contains(&secret_bytes));

    let exchange = wire::ExchangeRequest {
        account: "dev".into(),
        secret: Zeroizing::new("hunter2-password".into()),
        product: "prod".into(),
        hwid: [0; 32],
        challenge: [0; 32],
    };
    assert!(!format!("{exchange:?}").contains("hunter2-password"));

    let revoke = wire::RevokeRequest {
        admin_token: Zeroizing::new("admin-token-value".into()),
        target: wire::RevokeTarget::KeyId(1),
    };
    assert!(!format!("{revoke:?}").contains("admin-token-value"));
}

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
    assert_eq!(loaded.accounts[0].secret_hash, "$argon2id$v=19$fake");

    // A second save over the same path must work and leave no temp files.
    file.save(&path).expect("second save");
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name() != "accounts.json")
        .collect();
    assert!(leftovers.is_empty(), "stray temp files: {leftovers:?}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    std::fs::remove_dir_all(&dir).unwrap();
}

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
    assert!(
        !out.contains("supersecrethash"),
        "secret_hash leaked: {out}"
    );
}

#[test]
fn envelope_key_id_is_signed() {
    let issuer = Issuer::generate(1);
    let other = Issuer::generate(2);
    let challenge = Challenge::new();
    let session = Uuid::new_v4();
    let trusted = TrustedIssuers::new([(1, issuer.verifying_key()), (2, other.verifying_key())]);
    let now = Utc::now();

    let mut env = issue_valid(&issuer, &challenge, session);
    env.verify(&trusted, &expect_for(&challenge, &session, now))
        .expect("envelope under key 1 must verify");
    env.key_id = 2;
    assert!(matches!(
        env.verify(&trusted, &expect_for(&challenge, &session, now)),
        Err(KeystoneError::InvalidSignature)
    ));
}

#[test]
fn unknown_key_id_rejected() {
    let issuer = Issuer::generate(1);
    let rogue = Issuer::generate(7);
    let challenge = Challenge::new();
    let session = Uuid::new_v4();
    let env = issue_valid(&rogue, &challenge, session);
    assert!(matches!(
        env.verify(
            &trust_for(&issuer),
            &expect_for(&challenge, &session, Utc::now())
        ),
        Err(KeystoneError::UntrustedIssuer { key_id: 7 })
    ));
}

#[test]
fn revoked_key_id_rejected() {
    let (issuer, challenge, session) = setup();
    let mut trusted = trust_for(&issuer);
    let now = Utc::now();
    let env = issue_valid(&issuer, &challenge, session);
    env.verify(&trusted, &expect_for(&challenge, &session, now))
        .expect("envelope must verify before revocation");

    trusted.revoke(issuer.key_id());
    assert!(matches!(
        env.verify(&trusted, &expect_for(&challenge, &session, now)),
        Err(KeystoneError::UntrustedIssuer { key_id: 1 })
    ));
}

#[test]
fn multi_key_set_accepts_current_and_previous() {
    let previous = Issuer::generate(1);
    let current = Issuer::generate(2);
    let challenge = Challenge::new();
    let session = Uuid::new_v4();
    let mut trusted =
        TrustedIssuers::new([(1, previous.verifying_key()), (2, current.verifying_key())]);
    let now = Utc::now();

    let from_previous = issue_valid(&previous, &challenge, session);
    let from_current = issue_valid(&current, &challenge, session);
    from_previous
        .verify(&trusted, &expect_for(&challenge, &session, now))
        .expect("previous key still trusted");

    trusted.revoke(1);
    assert!(matches!(
        from_previous.verify(&trusted, &expect_for(&challenge, &session, now)),
        Err(KeystoneError::UntrustedIssuer { key_id: 1 })
    ));
    from_current
        .verify(&trusted, &expect_for(&challenge, &session, now))
        .expect("current key unaffected by revoking the previous one");
}

#[test]
fn manifest_key_id_is_signed() {
    let issuer = Issuer::generate(1);
    let other = Issuer::generate(2);
    let mut trusted =
        TrustedIssuers::new([(1, issuer.verifying_key()), (2, other.verifying_key())]);
    let now = Utc::now();

    let mut signed = SignedManifest::issue(&issuer, manifest_for(now));
    signed
        .verify(&trusted, now)
        .expect("manifest under key 1 must verify");

    signed.key_id = 2;
    assert!(matches!(
        signed.verify(&trusted, now),
        Err(KeystoneError::InvalidSignature)
    ));
    signed.key_id = 9;
    assert!(matches!(
        signed.verify(&trusted, now),
        Err(KeystoneError::UntrustedIssuer { key_id: 9 })
    ));
    signed.key_id = 1;
    trusted.revoke(1);
    assert!(matches!(
        signed.verify(&trusted, now),
        Err(KeystoneError::UntrustedIssuer { key_id: 1 })
    ));
}

#[test]
fn artifact_context_binds_epoch() {
    let secret = [0x5Au8; 32];
    let plaintext = b"payload bytes";
    let epoch0 = artifact_context("prod", "1.0.0", 0);
    let epoch1 = artifact_context("prod", "1.0.0", 1);

    let sealed = seal_artifact(&secret, &epoch0, plaintext).unwrap();
    let prefix: &[u8; SEALED_PREFIX_LEN] = sealed[..SEALED_PREFIX_LEN].try_into().unwrap();
    let key0 = artifact_key_from_prefix(&secret, &epoch0, prefix);
    let key1 = artifact_key_from_prefix(&secret, &epoch1, prefix);
    assert_eq!(
        decrypt_artifact(&key0, &sealed).unwrap().as_slice(),
        plaintext
    );
    assert!(matches!(
        decrypt_artifact(&key1, &sealed),
        Err(KeystoneError::InvalidMac)
    ));
}
