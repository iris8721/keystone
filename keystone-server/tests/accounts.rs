//! LocalAccounts: the file-backed entitlement source.

use std::path::{Path, PathBuf};
use std::task::Poll;
use std::time::{Duration as StdDuration, Instant};

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use chrono::{Duration, Utc};
use keystone_core::{AccountFile, AccountGrant, AccountRecord, EntitlementSource};
use keystone_server::accounts::LocalAccounts;

const ACCOUNT: &str = "dev";
const SECRET: &str = "devpass";
const PRODUCT: &str = "dev-product";

fn hash(secret: &str) -> String {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn record(name: &str, secret: &str, grants: Vec<AccountGrant>) -> AccountRecord {
    AccountRecord {
        name: name.to_string(),
        secret_hash: hash(secret),
        entitlements: grants,
        cert_sha256: None,
    }
}

fn grant(product: &str, days: i64, features: &[&str]) -> AccountGrant {
    AccountGrant {
        product: product.to_string(),
        expires_at: Utc::now() + Duration::days(days),
        features: features.iter().map(|f| f.to_string()).collect(),
    }
}

fn write(dir: &Path, accounts: Vec<AccountRecord>) -> PathBuf {
    let path = dir.join("accounts.json");
    AccountFile { accounts }.save(&path).unwrap();
    path
}

fn workdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keystone-accounts-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn credentials_and_grants_resolve() {
    let dir = workdir();
    let path = write(
        &dir,
        vec![record(ACCOUNT, SECRET, vec![grant(PRODUCT, 30, &["all"])])],
    );
    let backend = LocalAccounts::open(path);
    let identity = backend
        .authenticate(ACCOUNT, SECRET)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(identity.account, ACCOUNT);
    assert!(
        backend
            .authenticate(ACCOUNT, "wrong")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        backend
            .authenticate("nobody", SECRET)
            .await
            .unwrap()
            .is_none()
    );
    let grant = backend
        .entitlement(ACCOUNT, PRODUCT)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.features, ["all"]);
    assert!(
        backend
            .entitlement(ACCOUNT, "other")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn expired_grant_authorizes_nothing() {
    let dir = workdir();
    let path = write(
        &dir,
        vec![record(ACCOUNT, SECRET, vec![grant(PRODUCT, -1, &["all"])])],
    );
    let backend = LocalAccounts::open(path);
    assert!(
        backend
            .entitlement(ACCOUNT, PRODUCT)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn missing_or_malformed_file_is_a_backend_error() {
    let dir = workdir();
    let missing = LocalAccounts::open(dir.join("accounts.json"));
    assert!(missing.authenticate(ACCOUNT, SECRET).await.is_err());
    assert!(missing.entitlement(ACCOUNT, PRODUCT).await.is_err());

    let path = dir.join("broken.json");
    std::fs::write(&path, b"{not json").unwrap();
    let malformed = LocalAccounts::open(path);
    assert!(malformed.authenticate(ACCOUNT, SECRET).await.is_err());
}

#[tokio::test]
async fn a_cancelled_refresh_does_not_freeze_reloads() {
    let dir = workdir();
    let path = write(&dir, vec![]);
    let backend = LocalAccounts::open(path.clone());
    tokio::time::sleep(StdDuration::from_millis(1100)).await;

    // Start the once-per-second refresh, then drop the caller mid-way.
    let mut call = Box::pin(backend.entitlement(ACCOUNT, PRODUCT));
    let pending = std::future::poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx).is_pending())).await;
    assert!(pending, "the refresh finished before it could be cancelled");
    drop(call);

    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    write(
        &dir,
        vec![record(ACCOUNT, SECRET, vec![grant(PRODUCT, 30, &["all"])])],
    );
    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    assert!(
        backend
            .authenticate(ACCOUNT, SECRET)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn file_edits_are_picked_up_without_restart() {
    let dir = workdir();
    let path = write(&dir, vec![]);
    let backend = LocalAccounts::open(path.clone());
    assert!(
        backend
            .authenticate(ACCOUNT, SECRET)
            .await
            .unwrap()
            .is_none()
    );

    write(
        &dir,
        vec![record(ACCOUNT, SECRET, vec![grant(PRODUCT, 30, &["all"])])],
    );
    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    assert!(
        backend
            .authenticate(ACCOUNT, SECRET)
            .await
            .unwrap()
            .is_some()
    );

    std::fs::write(&path, b"{not json").unwrap();
    tokio::time::sleep(StdDuration::from_millis(1100)).await;
    assert!(backend.authenticate(ACCOUNT, SECRET).await.is_err());
}

#[tokio::test]
async fn cert_pin_is_decoded_and_validated() {
    let dir = workdir();
    let mut pinned = record(ACCOUNT, SECRET, vec![]);
    pinned.cert_sha256 = Some(hex::encode([0x11u8; 32]));
    let mut broken = record("broken", SECRET, vec![]);
    broken.cert_sha256 = Some("abcd".into());
    let path = write(&dir, vec![pinned, broken, record("free", SECRET, vec![])]);
    let backend = LocalAccounts::open(path);
    assert_eq!(
        backend.cert_sha256(ACCOUNT).await.unwrap(),
        Some([0x11; 32])
    );
    assert_eq!(backend.cert_sha256("free").await.unwrap(), None);
    assert!(backend.cert_sha256("broken").await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn password_hashing_does_not_block_the_executor() {
    let dir = workdir();
    let stored = hash(SECRET);
    let path = dir.join("accounts.json");
    AccountFile {
        accounts: vec![AccountRecord {
            name: ACCOUNT.into(),
            secret_hash: stored.clone(),
            entitlements: vec![],
            cert_sha256: None,
        }],
    }
    .save(&path)
    .unwrap();
    let backend = std::sync::Arc::new(LocalAccounts::open(path));

    let started = Instant::now();
    Argon2::default()
        .verify_password(SECRET.as_bytes(), &PasswordHash::new(&stored).unwrap())
        .unwrap();
    let one_verify = started.elapsed();

    let logins: Vec<_> = (0..16)
        .map(|_| {
            let backend = backend.clone();
            tokio::spawn(async move { backend.authenticate(ACCOUNT, SECRET).await })
        })
        .collect();
    let started = Instant::now();
    tokio::time::sleep(StdDuration::from_millis(5)).await;
    let tick = started.elapsed();
    for login in logins {
        assert!(login.await.unwrap().unwrap().is_some());
    }
    assert!(
        tick < (one_verify * 4).max(StdDuration::from_millis(50)),
        "timer delayed {tick:?} by hashing (one verify takes {one_verify:?})"
    );
}
