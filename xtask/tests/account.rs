//! `xtask account`: add → grant → list → revoke on a temp accounts file,
//! plus the refusal cases.

mod common;

use common::{ok, stdout, workdir, xtask};
use std::path::Path;
use std::process::{Output, Stdio};

fn account(root: &Path, args: &[&str]) -> Output {
    xtask(root)
        .arg("account")
        .args(args)
        .arg("--file")
        .arg(root.join("accounts.json"))
        .output()
        .unwrap()
}

#[test]
fn add_grant_list_revoke_roundtrip() {
    let root = workdir("account");
    let file = root.join("accounts.json");

    ok(account(&root, &["add", "alice", "--secret", "s3cret"]));
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("$argon2"), "expected argon2 hash in {text}");
    assert!(!text.contains("s3cret"), "plaintext secret leaked: {text}");

    ok(account(
        &root,
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
    ));

    let listing = stdout(&ok(account(&root, &["list"])));
    assert!(listing.contains("alice"), "{listing}");
    assert!(listing.contains("prod-x"), "{listing}");
    assert!(listing.contains("aim"), "{listing}");
    assert!(!listing.contains("$argon2"), "list leaked hash: {listing}");
    assert!(!listing.contains("s3cret"), "list leaked secret: {listing}");

    ok(account(&root, &["revoke", "alice", "--product", "prod-x"]));
    let listing = stdout(&ok(account(&root, &["list"])));
    assert!(listing.contains("alice"), "account vanished: {listing}");
    assert!(
        !listing.contains("prod-x"),
        "revoked grant listed: {listing}"
    );
}

#[test]
fn add_refuses_to_clobber_existing_account() {
    let root = workdir("account");
    ok(account(&root, &["add", "alice", "--secret", "one"]));
    let before = std::fs::read(root.join("accounts.json")).unwrap();
    let out = account(&root, &["add", "alice", "--secret", "two"]);
    assert!(!out.status.success(), "duplicate add must fail");
    assert_eq!(std::fs::read(root.join("accounts.json")).unwrap(), before);
}

/// Without a TTY the prompt reads piped stdin, keeping the secret out of argv.
#[test]
fn add_reads_secret_from_stdin_when_flag_absent() {
    let root = workdir("account");
    let file = root.join("accounts.json");
    let mut child = xtask(&root)
        .args(["account", "add", "bob", "--file"])
        .arg(&file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"piped-secret\n")
        .unwrap();
    ok(child.wait_with_output().unwrap());
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("$argon2"), "expected argon2 hash in {text}");
    assert!(!text.contains("piped-secret"), "plaintext leaked: {text}");
}

#[test]
fn add_with_secret_flag_warns_about_argv() {
    let root = workdir("account");
    let out = ok(account(&root, &["add", "carol", "--secret", "s3cret"]));
    assert!(String::from_utf8_lossy(&out.stderr).contains("argv"));
}

#[test]
fn revoke_missing_grant_fails_loudly() {
    let root = workdir("account");
    ok(account(&root, &["add", "alice", "--secret", "s3cret"]));
    let out = account(&root, &["revoke", "alice", "--product", "never-granted"]);
    assert!(!out.status.success());
}

/// Names the exchange request or a certificate file name would reject never reach the file.
#[test]
fn add_rejects_names_the_protocol_refuses() {
    let root = workdir("account");
    let long = "a".repeat(129);
    for name in ["bob smith", "CON", "trailing.", long.as_str()] {
        let out = account(&root, &["add", name, "--secret", "s3cret"]);
        assert!(!out.status.success(), "{name:?} must be rejected");
    }
    assert!(!root.join("accounts.json").exists());
    ok(account(
        &root,
        &["add", &"a".repeat(128), "--secret", "s3cret"],
    ));
}

#[test]
fn grant_rejects_products_the_protocol_refuses() {
    let root = workdir("account");
    ok(account(&root, &["add", "alice", "--secret", "s3cret"]));
    let before = std::fs::read(root.join("accounts.json")).unwrap();
    let long = "p".repeat(65);
    for product in ["Studio Pro", "../x", long.as_str()] {
        let out = account(
            &root,
            &["grant", "alice", "--product", product, "--days", "30"],
        );
        assert!(!out.status.success(), "{product:?} must be rejected");
    }
    assert_eq!(std::fs::read(root.join("accounts.json")).unwrap(), before);
}

/// A non-positive grant is born expired: reject it and write nothing.
#[test]
fn grant_rejects_nonpositive_days() {
    let root = workdir("account");
    ok(account(&root, &["add", "alice", "--secret", "s3cret"]));
    for days in ["0", "-7"] {
        let out = account(
            &root,
            &["grant", "alice", "--product", "prod-x", "--days", days],
        );
        assert!(!out.status.success(), "--days {days} must be rejected");
    }
    let listing = stdout(&ok(account(&root, &["list"])));
    assert!(!listing.contains("prod-x"), "{listing}");
}

/// Windows has no mode bits: the accounts file must end up owner-only.
#[cfg(windows)]
#[test]
fn accounts_file_is_owner_only_on_windows() {
    let root = workdir("account");
    ok(account(&root, &["add", "alice", "--secret", "s3cret"]));
    let out = std::process::Command::new("icacls")
        .arg(root.join("accounts.json"))
        .output()
        .unwrap();
    let acl = String::from_utf8_lossy(&out.stdout);
    let user = std::env::var("USERNAME").unwrap();
    let grants: Vec<&str> = acl.lines().filter(|l| l.contains(":(")).collect();
    assert_eq!(grants.len(), 1, "expected a single ACE: {acl}");
    assert!(
        grants[0].contains(&user),
        "ACE is not the current user: {acl}"
    );
    assert!(!acl.contains("(I)"), "inherited ACEs remain: {acl}");
}
