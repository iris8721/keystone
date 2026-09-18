//! `xtask seal` writes the sealed blob plus the `.build` sidecar the
//! server stamps into manifests and download records, and a `.sha256`
//! sidecar carrying the hex sha256 of the PLAINTEXT artifact so the
//! server can skip per-request decryption.

use std::path::PathBuf;
use std::process::Command;

const PAYLOAD_SECRET: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn workdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keystone-xtask-seal-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn seal(dir: &std::path::Path, extra: &[&str]) -> std::process::Output {
    seal_with_epoch(dir, extra, None)
}

fn seal_with_epoch(
    dir: &std::path::Path,
    extra: &[&str],
    epoch: Option<u32>,
) -> std::process::Output {
    let input = dir.join("payload.bin");
    std::fs::write(&input, b"release bytes").unwrap();
    let out_dir = dir.join("out");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_xtask"));
    cmd.arg("seal")
        .args(["--product", "prod", "--version", "1.0.0"])
        .arg("--in")
        .arg(&input)
        .arg("--out")
        .arg(&out_dir)
        .args(extra)
        .env("KEYSTONE_PAYLOAD_SECRET", PAYLOAD_SECRET)
        .env_remove("KEYSTONE_PAYLOAD_EPOCH");
    if let Some(e) = epoch {
        cmd.env("KEYSTONE_PAYLOAD_EPOCH", e.to_string());
    }
    cmd.output().unwrap()
}

#[test]
fn seal_writes_build_id_sidecar() {
    let dir = workdir();
    let out = seal(&dir, &["--build-id", "release-2026-09"]);
    assert!(out.status.success(), "seal failed: {:?}", out);
    let out_dir = dir.join("out");
    assert!(out_dir.join("prod-1.0.0.bin").is_file());
    let build_id = std::fs::read_to_string(out_dir.join("prod-1.0.0.build")).unwrap();
    assert_eq!(build_id, "release-2026-09");
}

#[test]
fn seal_defaults_to_random_build_id() {
    let dir = workdir();
    let out = seal(&dir, &[]);
    assert!(out.status.success(), "seal failed: {:?}", out);
    let build_id = std::fs::read_to_string(dir.join("out").join("prod-1.0.0.build")).unwrap();
    assert_eq!(build_id.len(), 16, "default is a random 16-hex id");
    assert!(build_id.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn seal_writes_plaintext_sha256_sidecar() {
    let dir = workdir();
    let out = seal(&dir, &[]);
    assert!(out.status.success(), "seal failed: {out:?}");
    let recorded = std::fs::read_to_string(dir.join("out").join("prod-1.0.0.sha256")).unwrap();
    use sha2::{Digest, Sha256};
    let expected = hex::encode(Sha256::digest(b"release bytes"));
    assert_eq!(recorded, expected, "sidecar must hash the plaintext");
}

/// The seal↔serve contract: a blob `xtask seal` writes must decrypt
/// under the key the server derives — HKDF(secret, blob nonce,
/// artifact_context(product, version, epoch)). Sealing under any other
/// context (e.g. the ambiguous "{product}:{version}" string) produces
/// artifacts the server can never attest.
#[test]
fn sealed_blob_decrypts_under_server_derived_key() {
    let dir = workdir();
    let out = seal(&dir, &[]);
    assert!(out.status.success(), "seal failed: {out:?}");

    let blob = std::fs::read(dir.join("out").join("prod-1.0.0.bin")).unwrap();
    let secret: [u8; 32] = hex::decode(PAYLOAD_SECRET).unwrap().try_into().unwrap();
    // Exactly what routes.rs does: context from artifact_context (epoch
    // 0 — the default when KEYSTONE_PAYLOAD_EPOCH is unset), key from
    // the blob's own nonce prefix.
    let key = keystone_core::artifact_key_for(
        &secret,
        &keystone_core::artifact_context("prod", "1.0.0", 0),
        &blob,
    )
    .expect("server-side key derivation must succeed");
    let plaintext = keystone_core::decrypt_artifact(&key, &blob)
        .expect("sealed artifact must decrypt under the server's key");
    assert_eq!(plaintext, b"release bytes");

    // And the wrong context must NOT open it — the binding is real.
    let wrong = keystone_core::artifact_key_for(&secret, b"prod:1.0.0", &blob).unwrap();
    assert!(keystone_core::decrypt_artifact(&wrong, &blob).is_err());
}

/// README: payload keys are HKDF(secret ‖ … ‖ epoch). Bumping
/// KEYSTONE_PAYLOAD_EPOCH after a secret rotation must make every blob
/// sealed under the previous epoch unopenable — the server derives with
/// its own epoch and nothing else. A blob sealed at epoch 3 must open
/// at epoch 3 and fail at epoch 0.
#[test]
fn seal_binds_payload_epoch() {
    let dir = workdir();
    let out = seal_with_epoch(&dir, &[], Some(3));
    assert!(out.status.success(), "seal failed: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("epoch 3"),
        "seal must report the epoch it sealed under"
    );

    let blob = std::fs::read(dir.join("out").join("prod-1.0.0.bin")).unwrap();
    let secret: [u8; 32] = hex::decode(PAYLOAD_SECRET).unwrap().try_into().unwrap();

    let right = keystone_core::artifact_key_for(
        &secret,
        &keystone_core::artifact_context("prod", "1.0.0", 3),
        &blob,
    )
    .unwrap();
    assert_eq!(
        keystone_core::decrypt_artifact(&right, &blob).unwrap(),
        b"release bytes"
    );

    let stale = keystone_core::artifact_key_for(
        &secret,
        &keystone_core::artifact_context("prod", "1.0.0", 0),
        &blob,
    )
    .unwrap();
    assert!(
        keystone_core::decrypt_artifact(&stale, &blob).is_err(),
        "a server on epoch 0 must not open an epoch-3 blob"
    );
}

/// A non-numeric epoch is an operator error, not a silent fallback to 0.
#[test]
fn seal_rejects_malformed_epoch() {
    let dir = workdir();
    let input = dir.join("payload.bin");
    std::fs::write(&input, b"release bytes").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("seal")
        .args(["--product", "prod", "--version", "1.0.0"])
        .arg("--in")
        .arg(&input)
        .arg("--out")
        .arg(dir.join("out"))
        .env("KEYSTONE_PAYLOAD_SECRET", PAYLOAD_SECRET)
        .env("KEYSTONE_PAYLOAD_EPOCH", "latest")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("KEYSTONE_PAYLOAD_EPOCH"));
    assert!(!dir.join("out").join("prod-1.0.0.bin").exists());
}
