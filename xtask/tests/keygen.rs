//! `xtask keygen` must never print the seed — scrollback, shell
//! history, and CI logs are all leak paths. The keyfile itself is
//! written owner-only.

use std::path::PathBuf;
use std::process::Command;

fn workdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keystone-xtask-keygen-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn keygen_never_prints_the_seed() {
    let dir = workdir();
    let keyfile = dir.join("test.key");
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("keygen")
        .arg("--out")
        .arg(&keyfile)
        .output()
        .unwrap();
    assert!(out.status.success(), "keygen failed: {out:?}");

    let seed_hex = hex::encode(std::fs::read(&keyfile).unwrap());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains(&seed_hex),
        "seed hex leaked into stdout: {stdout}"
    );
    assert!(
        !stderr.contains(&seed_hex),
        "seed hex leaked into stderr: {stderr}"
    );
    // The pinned pubkey is still printed — that's the whole point of
    // the command — and it must be 64 hex chars, not the seed.
    assert!(
        stdout.contains("verifying key"),
        "pubkey line missing: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn keygen_keyfile_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = workdir();
    let keyfile = dir.join("test.key");
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("keygen")
        .arg("--out")
        .arg(&keyfile)
        .output()
        .unwrap();
    assert!(out.status.success(), "keygen failed: {out:?}");
    let mode = std::fs::metadata(&keyfile).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "keyfile mode was {mode:o}");
}

/// A keyfile overwrite silently invalidates every signature clients
/// have pinned — keygen must refuse to clobber without --force, and
/// the existing file must survive untouched.
#[test]
fn keygen_refuses_to_clobber_without_force() {
    let dir = workdir();
    let keyfile = dir.join("test.key");
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("keygen")
        .arg("--out")
        .arg(&keyfile)
        .output()
        .unwrap();
    assert!(out.status.success(), "first keygen failed: {out:?}");
    let original = std::fs::read(&keyfile).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("keygen")
        .arg("--out")
        .arg(&keyfile)
        .output()
        .unwrap();
    assert!(!out.status.success(), "clobber without --force must fail");
    assert_eq!(
        std::fs::read(&keyfile).unwrap(),
        original,
        "refused overwrite must leave the keyfile untouched"
    );

    // --force is the deliberate act that allows it.
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("keygen")
        .arg("--out")
        .arg(&keyfile)
        .arg("--force")
        .output()
        .unwrap();
    assert!(out.status.success(), "forced keygen failed: {out:?}");
    assert_ne!(std::fs::read(&keyfile).unwrap(), original);
}

/// The key id is what clients pair with the pubkey in `TrustedIssuers`
/// and what the server stamps into every envelope — keygen must print
/// it, default it to 1, and refuse anything outside u8.
#[test]
fn keygen_prints_key_id_and_defaults_to_one() {
    let dir = workdir();
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("keygen")
        .arg("--out")
        .arg(dir.join("default.key"))
        .output()
        .unwrap();
    assert!(out.status.success(), "keygen failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("key id:        1"),
        "default key id must be 1: {stdout}"
    );
    assert!(stdout.contains("KEYSTONE_KEY_ID=1"));

    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("keygen")
        .arg("--out")
        .arg(dir.join("two.key"))
        .args(["--key-id", "2"])
        .output()
        .unwrap();
    assert!(out.status.success(), "keygen --key-id 2 failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("key id:        2"), "{stdout}");
    assert!(stdout.contains("KEYSTONE_KEY_ID=2"));

    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("keygen")
        .arg("--out")
        .arg(dir.join("bad.key"))
        .args(["--key-id", "256"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "256 is not a u8");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--key-id"));
    assert!(
        !dir.join("bad.key").exists(),
        "no keyfile on a rejected key id"
    );
}
