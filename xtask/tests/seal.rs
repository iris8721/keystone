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
        .env("KEYSTONE_PAYLOAD_SECRET", PAYLOAD_SECRET);
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
    let build_id =
        std::fs::read_to_string(dir.join("out").join("prod-1.0.0.build")).unwrap();
    assert_eq!(build_id.len(), 16, "default is a random 16-hex id");
    assert!(build_id.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn seal_writes_plaintext_sha256_sidecar() {
    let dir = workdir();
    let out = seal(&dir, &[]);
    assert!(out.status.success(), "seal failed: {out:?}");
    let recorded =
        std::fs::read_to_string(dir.join("out").join("prod-1.0.0.sha256")).unwrap();
    use sha2::{Digest, Sha256};
    let expected = hex::encode(Sha256::digest(b"release bytes"));
    assert_eq!(recorded, expected, "sidecar must hash the plaintext");
}

/// The seal↔serve contract: a blob `xtask seal` writes must decrypt
/// under the key the server derives — HKDF(secret, blob nonce,
/// artifact_context(product, version)). Sealing under any other
/// context (e.g. the ambiguous "{product}:{version}" string) produces
/// artifacts the server can never attest.
#[test]
fn sealed_blob_decrypts_under_server_derived_key() {
    let dir = workdir();
    let out = seal(&dir, &[]);
    assert!(out.status.success(), "seal failed: {out:?}");

    let blob = std::fs::read(dir.join("out").join("prod-1.0.0.bin")).unwrap();
    let secret: [u8; 32] = hex::decode(PAYLOAD_SECRET).unwrap().try_into().unwrap();
    // Exactly what routes.rs does: context from artifact_context, key
    // from the blob's own nonce prefix.
    let key = keystone_core::artifact_key_for(
        &secret,
        &keystone_core::artifact_context("prod", "1.0.0"),
        &blob,
    )
    .expect("server-side key derivation must succeed");
    let plaintext = keystone_core::decrypt_artifact(&key, &blob)
        .expect("sealed artifact must decrypt under the server's key");
    assert_eq!(plaintext, b"release bytes");

    // And the wrong context must NOT open it — the binding is real.
    let wrong = keystone_core::artifact_key_for(
        &secret,
        b"prod:1.0.0",
        &blob,
    )
    .unwrap();
    assert!(keystone_core::decrypt_artifact(&wrong, &blob).is_err());
}
