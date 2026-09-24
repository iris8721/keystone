//! `xtask verify` passes a fully provisioned root and fails each
//! condition the server refuses to start under.

mod common;

use common::{cert_der, ok, run, sha256_hex, stdout, workdir, xtask};
use std::path::{Path, PathBuf};
use std::process::Output;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn provisioned() -> PathBuf {
    let root = workdir("verify");
    ok(run(&root, &["keygen", "--key-id", "1"]));
    ok(run(&root, &["ca"]));
    ok(run(&root, &["cert"]));
    ok(run(&root, &["issue-cert", "keystone-admin"]));
    ok(run(
        &root,
        &["account", "add", "alice", "--secret", "s3cret"],
    ));
    root
}

/// Runs with a valid admin token and the admin cert's hash unless `env` overrides them.
fn verify(root: &Path, env: &[(&str, &str)]) -> Output {
    let admin = sha256_hex(&cert_der(&root.join("keystone-admin-cert.pem")));
    let mut cmd = xtask(root);
    cmd.arg("verify")
        .env("KEYSTONE_ADMIN_TOKEN", TOKEN)
        .env("KEYSTONE_ADMIN_CERT_SHA256", admin);
    for (name, value) in env {
        cmd.env(name, value);
    }
    cmd.output().unwrap()
}

#[track_caller]
fn assert_fails(out: &Output, label: &str) {
    assert!(!out.status.success(), "verify must fail: {out:?}");
    let text = stdout(out);
    assert!(
        text.contains(&format!("[FAIL] {label}")),
        "expected {label} failure: {text}"
    );
}

#[test]
fn verify_rejects_short_admin_token() {
    let root = provisioned();
    ok(verify(&root, &[]));
    let out = verify(&root, &[("KEYSTONE_ADMIN_TOKEN", &TOKEN[1..])]);
    assert_fails(&out, "KEYSTONE_ADMIN_TOKEN");
}

#[test]
fn verify_rejects_revoked_active_key() {
    let root = provisioned();
    let out = verify(&root, &[("KEYSTONE_REVOKED_KEY_IDS", "3, 1")]);
    assert_fails(&out, "active key");
    ok(verify(&root, &[("KEYSTONE_REVOKED_KEY_IDS", "3")]));

    std::fs::write(root.join("revoked-keys.json"), "[2, 1]").unwrap();
    assert_fails(&verify(&root, &[]), "active key");
    std::fs::write(root.join("revoked-keys.json"), "[2]").unwrap();
    ok(verify(&root, &[]));
}

#[test]
fn verify_checks_payload_layout() {
    let root = provisioned();
    ok(run(&root, &["payload-secret"]));
    let input = root.join("app.exe");
    std::fs::write(&input, b"release bytes").unwrap();
    ok(xtask(&root)
        .args(["seal", "--product", "prod", "--version", "1.0.0", "--in"])
        .arg(&input)
        .output()
        .unwrap());
    ok(verify(&root, &[]));

    std::fs::remove_file(root.join("payloads").join("prod").join("1.0.0.sha256")).unwrap();
    assert_fails(&verify(&root, &[]), "payload layout");
}

/// Under mTLS the admin listener needs an allow-list of well-formed leaf hashes.
#[test]
fn verify_requires_admin_cert_hashes_under_mtls() {
    let root = provisioned();
    let admin = sha256_hex(&cert_der(&root.join("keystone-admin-cert.pem")));
    let pair = format!("{admin}, {}", "AB".repeat(32));
    ok(verify(&root, &[("KEYSTONE_ADMIN_CERT_SHA256", &pair)]));
    for bad in ["zz", &admin[1..], ","] {
        let out = verify(&root, &[("KEYSTONE_ADMIN_CERT_SHA256", bad)]);
        assert_fails(&out, "KEYSTONE_ADMIN_CERT_SHA256");
    }

    let out = xtask(&root)
        .arg("verify")
        .env("KEYSTONE_ADMIN_TOKEN", TOKEN)
        .output()
        .unwrap();
    assert_fails(&out, "KEYSTONE_ADMIN_CERT_SHA256");
    // No admin token: no admin listener, nothing to allow-list.
    ok(xtask(&root).arg("verify").output().unwrap());
}

#[test]
fn verify_flags_account_records_the_protocol_refuses() {
    let root = provisioned();
    let path = root.join("accounts.json");
    let mut file = keystone_core::AccountFile::load(&path).unwrap();
    file.accounts[0]
        .entitlements
        .push(keystone_core::AccountGrant {
            product: "Studio Pro".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            features: vec![],
        });
    file.save(&path).unwrap();
    assert_fails(&verify(&root, &[]), "accounts");

    file.accounts[0].entitlements.clear();
    file.accounts[0].name = "bob smith".into();
    file.save(&path).unwrap();
    assert_fails(&verify(&root, &[]), "accounts");
}
