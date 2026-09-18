//! LocalAccounts — the file-backed entitlement source. Covers the
//! contract the routes rely on: good creds authenticate, bad creds and
//! unknown accounts deny identically (argon2 cost paid either way),
//! expired grants authorize nothing, backend failures are errors not
//! denials, and file edits are picked up without a restart.

use std::path::PathBuf;
use std::time::{Duration as StdDuration, Instant, SystemTime};

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use argon2::Argon2;
use chrono::{Duration, Utc};
use keystone_core::{AccountFile, AccountGrant, AccountRecord, EntitlementSource};
use keystone_server::accounts::LocalAccounts;

const ACCOUNT: &str = "alice";
const SECRET: &str = "s3cret";
const PRODUCT: &str = "prod-x";

fn hash(secret: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn grant(product: &str, expires_at: chrono::DateTime<Utc>) -> AccountGrant {
    AccountGrant {
        product: product.to_string(),
        expires_at,
        features: vec!["aim".to_string(), "esp".to_string()],
    }
}

fn record(name: &str, secret: &str, grants: Vec<AccountGrant>) -> AccountRecord {
    AccountRecord {
        name: name.to_string(),
        secret_hash: hash(secret),
        entitlements: grants,
        cert_sha256: None,
    }
}

fn workdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keystone-accounts-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_accounts(dir: &std::path::Path, file: &AccountFile) -> PathBuf {
    let path = dir.join("accounts.json");
    file.save(&path).unwrap();
    path
}

#[tokio::test]
async fn good_credentials_authenticate_and_grant() {
    let dir = workdir();
    let path = write_accounts(
        &dir,
        &AccountFile {
            accounts: vec![record(
                ACCOUNT,
                SECRET,
                vec![grant(PRODUCT, Utc::now() + Duration::days(30))],
            )],
        },
    );
    let backend = LocalAccounts::open(path);

    let identity = backend.authenticate(ACCOUNT, SECRET).await.unwrap();
    assert_eq!(identity.unwrap().account, ACCOUNT);

    let grant = backend.entitlement(ACCOUNT, PRODUCT).await.unwrap().unwrap();
    assert_eq!(grant.account, ACCOUNT);
    assert_eq!(grant.product, PRODUCT);
    assert_eq!(grant.features, vec!["aim", "esp"]);
}

#[tokio::test]
async fn bad_secret_denies() {
    let dir = workdir();
    let path = write_accounts(
        &dir,
        &AccountFile {
            accounts: vec![record(
                ACCOUNT,
                SECRET,
                vec![grant(PRODUCT, Utc::now() + Duration::days(30))],
            )],
        },
    );
    let backend = LocalAccounts::open(path);
    assert!(backend.authenticate(ACCOUNT, "wrong").await.unwrap().is_none());
}

#[tokio::test]
async fn unknown_account_denies_with_argon2_cost_paid() {
    let dir = workdir();
    let path = write_accounts(
        &dir,
        &AccountFile {
            accounts: vec![record(
                ACCOUNT,
                SECRET,
                vec![grant(PRODUCT, Utc::now() + Duration::days(30))],
            )],
        },
    );
    let backend = LocalAccounts::open(path);

    // The denial must cost an argon2 verify — a fast-path return would
    // leak account existence through timing. Argon2's default params
    // take milliseconds at minimum; a skipped verify is sub-microsecond.
    let start = Instant::now();
    let result = backend.authenticate("nobody", SECRET).await.unwrap();
    assert!(result.is_none());
    assert!(
        start.elapsed() >= StdDuration::from_millis(1),
        "unknown-account verify returned suspiciously fast — timing oracle open"
    );
}

#[tokio::test]
async fn expired_grant_authorizes_nothing() {
    let dir = workdir();
    let path = write_accounts(
        &dir,
        &AccountFile {
            accounts: vec![record(
                ACCOUNT,
                SECRET,
                vec![grant(PRODUCT, Utc::now() - Duration::days(1))],
            )],
        },
    );
    let backend = LocalAccounts::open(path);
    // Credentials still prove identity — expiry is an authorization
    // failure, not an authentication one.
    assert!(backend.authenticate(ACCOUNT, SECRET).await.unwrap().is_some());
    assert!(backend.entitlement(ACCOUNT, PRODUCT).await.unwrap().is_none());
}

#[tokio::test]
async fn missing_file_is_a_backend_error() {
    let dir = workdir();
    let backend = LocalAccounts::open(dir.join("accounts.json"));
    assert!(backend.authenticate(ACCOUNT, SECRET).await.is_err());
    assert!(backend.entitlement(ACCOUNT, PRODUCT).await.is_err());
}

#[tokio::test]
async fn malformed_file_is_a_backend_error() {
    let dir = workdir();
    let path = dir.join("accounts.json");
    std::fs::write(&path, b"{not json").unwrap();
    let backend = LocalAccounts::open(path);
    assert!(backend.authenticate(ACCOUNT, SECRET).await.is_err());
    assert!(backend.entitlement(ACCOUNT, PRODUCT).await.is_err());
}

#[tokio::test]
async fn file_edits_are_picked_up_without_restart() {
    let dir = workdir();
    let path = write_accounts(&dir, &AccountFile { accounts: vec![] });
    let backend = LocalAccounts::open(path.clone());
    assert!(backend.authenticate(ACCOUNT, SECRET).await.unwrap().is_none());

    // Rewrite the file with the account added, and bump the mtime past
    // the previous write — filesystems with coarse mtime granularity
    // must still observe the change.
    AccountFile {
        accounts: vec![record(
            ACCOUNT,
            SECRET,
            vec![grant(PRODUCT, Utc::now() + Duration::days(30))],
        )],
    }
    .save(&path)
    .unwrap();
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(SystemTime::now() + StdDuration::from_secs(5))
        .unwrap();

    assert!(backend.authenticate(ACCOUNT, SECRET).await.unwrap().is_some());
    assert!(backend.entitlement(ACCOUNT, PRODUCT).await.unwrap().is_some());
}

#[tokio::test]
async fn cert_sha256_decodes_the_recorded_fingerprint() {
    let dir = workdir();
    let mut rec = record(ACCOUNT, SECRET, vec![]);
    rec.cert_sha256 = Some(hex::encode([0xABu8; 32]));
    let path = write_accounts(
        &dir,
        &AccountFile {
            accounts: vec![rec, record("unbound", SECRET, vec![])],
        },
    );
    let backend = LocalAccounts::open(path);

    assert_eq!(
        backend.cert_sha256(ACCOUNT).await.unwrap(),
        Some([0xABu8; 32])
    );
    assert_eq!(backend.cert_sha256("unbound").await.unwrap(), None);
    assert_eq!(backend.cert_sha256("nobody").await.unwrap(), None);
}

/// A cert_sha256 that isn't 32 bytes of hex is a backend error, not a
/// silent "unbound" — a malformed pin must fail closed, never open.
#[tokio::test]
async fn malformed_cert_sha256_is_a_backend_error() {
    let dir = workdir();
    let mut bad_hex = record(ACCOUNT, SECRET, vec![]);
    bad_hex.cert_sha256 = Some("not-hex-at-all".into());
    let mut short = record("short", SECRET, vec![]);
    short.cert_sha256 = Some(hex::encode([0xABu8; 16])); // 16 bytes, not 32
    let path = write_accounts(
        &dir,
        &AccountFile {
            accounts: vec![bad_hex, short],
        },
    );
    let backend = LocalAccounts::open(path);

    assert!(
        backend.cert_sha256(ACCOUNT).await.is_err(),
        "non-hex cert_sha256 must error, not silently unbind"
    );
    assert!(
        backend.cert_sha256("short").await.is_err(),
        "short cert_sha256 must error, not silently unbind"
    );
}

/// A stored secret_hash that argon2 can't parse is a backend failure
/// (503 upstream), not a denial — a corrupt file must not masquerade
/// as "bad credentials".
#[tokio::test]
async fn corrupt_secret_hash_is_a_backend_error() {
    let dir = workdir();
    let mut rec = record(ACCOUNT, SECRET, vec![]);
    rec.secret_hash = "not-an-argon2-phc-string".into();
    let path = write_accounts(&dir, &AccountFile { accounts: vec![rec] });
    let backend = LocalAccounts::open(path);

    assert!(
        backend.authenticate(ACCOUNT, SECRET).await.is_err(),
        "corrupt hash must be a backend error, not a denial"
    );
}
