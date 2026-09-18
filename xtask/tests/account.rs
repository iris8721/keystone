//! `xtask account` — the operator-facing account management commands.
//! Roundtrip on a temp accounts file: add → grant → list → revoke,
//! plus the refusal cases (duplicate add, missing CA for cert).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workdir() -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("keystone-xtask-account-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn account(dir: &std::path::Path, args: &[&str]) -> Output {
    let file = dir.join("accounts.json");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_xtask"));
    cmd.arg("account")
        .args(args)
        .arg("--file")
        .arg(&file)
        // Point CA lookups at guaranteed-missing paths so `account cert`
        // can't accidentally find real CA material from the workspace.
        .env("KEYSTONE_CA_CERT", dir.join("no-ca-cert.pem"))
        .env("KEYSTONE_CA_KEY", dir.join("no-ca-key.pem"));
    cmd.output().unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn add_grant_list_revoke_roundtrip() {
    let dir = workdir();
    let file = dir.join("accounts.json");

    let out = account(&dir, &["add", "alice", "--secret", "s3cret"]);
    assert!(out.status.success(), "add failed: {out:?}");
    let text = std::fs::read_to_string(&file).unwrap();
    // The file holds an argon2 PHC string — never the plaintext secret.
    assert!(text.contains("$argon2"), "expected argon2 hash in {text}");
    assert!(
        !text.contains("s3cret"),
        "plaintext secret leaked into {text}"
    );

    let out = account(
        &dir,
        &[
            "grant",
            "alice",
            "--product",
            "prod-x",
            "--days",
            "30",
            "--features",
            "aim,esp",
        ],
    );
    assert!(out.status.success(), "grant failed: {out:?}");

    let out = account(&dir, &["list"]);
    assert!(out.status.success(), "list failed: {out:?}");
    let listing = stdout(&out);
    assert!(listing.contains("alice"), "list missing account: {listing}");
    assert!(
        listing.contains("prod-x"),
        "list missing product: {listing}"
    );
    assert!(listing.contains("aim"), "list missing features: {listing}");
    // Hashes and secrets are operator-invisible.
    assert!(!listing.contains("$argon2"), "list leaked hash: {listing}");
    assert!(!listing.contains("s3cret"), "list leaked secret: {listing}");

    let out = account(&dir, &["revoke", "alice", "--product", "prod-x"]);
    assert!(out.status.success(), "revoke failed: {out:?}");
    let out = account(&dir, &["list"]);
    let listing = stdout(&out);
    assert!(listing.contains("alice"), "account vanished: {listing}");
    assert!(
        !listing.contains("prod-x"),
        "revoked product still listed: {listing}"
    );
}

#[test]
fn add_refuses_to_clobber_existing_account() {
    let dir = workdir();
    assert!(
        account(&dir, &["add", "alice", "--secret", "one"])
            .status
            .success()
    );
    let out = account(&dir, &["add", "alice", "--secret", "two"]);
    assert!(!out.status.success(), "duplicate add must fail");
    // The original account is untouched.
    let out = account(&dir, &["list"]);
    assert!(stdout(&out).contains("alice"));
}

#[test]
fn add_prompts_for_secret_when_flag_absent() {
    // Headless run: no TTY, so the prompt path reads piped stdin
    // verbatim — this is also how scripts feed the secret without argv.
    let dir = workdir();
    let file = dir.join("accounts.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["account", "add", "bob"])
        .arg("--file")
        .arg(&file)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"piped-secret\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "prompted add failed: {out:?}");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("$argon2"), "expected argon2 hash in {text}");
    assert!(
        !text.contains("piped-secret"),
        "plaintext secret leaked into {text}"
    );
}

#[test]
fn add_with_secret_flag_warns_about_argv() {
    let dir = workdir();
    let out = account(&dir, &["add", "carol", "--secret", "s3cret"]);
    assert!(out.status.success(), "add failed: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("argv"),
        "expected argv-leak warning on stderr: {stderr}"
    );
}

#[test]
fn revoke_missing_grant_fails_loudly() {
    let dir = workdir();
    assert!(
        account(&dir, &["add", "alice", "--secret", "s3cret"])
            .status
            .success()
    );
    let out = account(&dir, &["revoke", "alice", "--product", "never-granted"]);
    assert!(
        !out.status.success(),
        "revoking a grant that doesn't exist must fail"
    );
}

#[test]
fn cert_without_ca_material_errors() {
    let dir = workdir();
    assert!(
        account(&dir, &["add", "alice", "--secret", "s3cret"])
            .status
            .success()
    );
    let out = account(&dir, &["cert", "alice"]);
    assert!(!out.status.success(), "cert without a CA must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("mTLS") || stderr.contains("CA"),
        "error should name the missing CA: {stderr}"
    );
}

#[test]
fn cert_with_ca_records_cert_sha256() {
    let dir = workdir();
    // Mint a throwaway CA the way `cargo xtask ca` does, pointed at by
    // the env overrides so the workspace stays untouched.
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "keystone-ca");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let ca_cert = params.self_signed(&key_pair).unwrap();
    let ca_cert_path = dir.join("ca-cert.pem");
    let ca_key_path = dir.join("ca-key.pem");
    std::fs::write(&ca_cert_path, ca_cert.pem()).unwrap();
    std::fs::write(&ca_key_path, key_pair.serialize_pem()).unwrap();

    // Unique account name: the cert PEMs land at the workspace root and
    // must be cleaned up rather than clobbering anything real.
    let name = format!("test-acct-{}", rand::random::<u64>());
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let cert_pem = root.join(format!("{name}-cert.pem"));
    let key_pem = root.join(format!("{name}-key.pem"));

    assert!(
        account(&dir, &["add", &name, "--secret", "s3cret"])
            .status
            .success()
    );
    let file = dir.join("accounts.json");
    let out = {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_xtask"));
        cmd.args(["account", "cert", &name])
            .arg("--file")
            .arg(&file)
            .env("KEYSTONE_CA_CERT", &ca_cert_path)
            .env("KEYSTONE_CA_KEY", &ca_key_path);
        cmd.output().unwrap()
    };
    assert!(out.status.success(), "cert failed: {out:?}");
    assert!(cert_pem.is_file(), "client cert not written");
    assert!(key_pem.is_file(), "client key not written");

    // The recorded fingerprint must be the sha256 of the issued cert's
    // DER — the value the server compares the TLS peer cert against.
    let pem_text = std::fs::read_to_string(&cert_pem).unwrap();
    let der = pem_text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>();
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(der)
        .unwrap();
    use sha2::{Digest, Sha256};
    let expected = hex::encode(Sha256::digest(&der));
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(
        text.contains(&expected),
        "cert_sha256 not recorded on account: {text}"
    );

    let _ = std::fs::remove_file(&cert_pem);
    let _ = std::fs::remove_file(&key_pem);
}

/// `account cert` on an account that doesn't exist must fail before
/// any CA work — a typo'd name must not mint a cert.
#[test]
fn cert_on_nonexistent_account_errors() {
    let dir = workdir();
    let out = account(&dir, &["cert", "ghost"]);
    assert!(
        !out.status.success(),
        "cert for a missing account must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ghost"),
        "error should name the missing account: {stderr}"
    );
}

/// `--days 0` mints a grant that is already expired — a dead grant
/// that looks live in the file. Non-positive days must be rejected.
#[test]
fn grant_rejects_nonpositive_days() {
    let dir = workdir();
    assert!(
        account(&dir, &["add", "alice", "--secret", "s3cret"])
            .status
            .success()
    );
    for days in ["0", "-7"] {
        let out = account(
            &dir,
            &["grant", "alice", "--product", "prod-x", "--days", days],
        );
        assert!(
            !out.status.success(),
            "grant --days {days} must be rejected"
        );
    }
    // And nothing was written — the account still has no grants.
    let out = account(&dir, &["list"]);
    let listing = stdout(&out);
    assert!(
        !listing.contains("prod-x"),
        "rejected grant must not land in the file: {listing}"
    );
}
