//! `xtask seal`: `{dir}/{product}/{version}.bin` plus `.sha256` (hex of
//! the plaintext) and `.build` sidecars, sealed under the key the server
//! derives from the blob prefix.

mod common;

use common::{ok, sha256_hex, stdout, workdir, xtask};
use keystone_core::{ArtifactPaths, SEALED_PREFIX_LEN};
use std::path::{Path, PathBuf};
use std::process::Output;

const SECRET: [u8; 32] = [0x5a; 32];
const PLAINTEXT: &[u8] = b"release bytes";

fn seal(root: &Path, product: &str, extra: &[&str], epoch: Option<&str>) -> Output {
    let input = root.join("payload.bin");
    std::fs::write(&input, PLAINTEXT).unwrap();
    let secret = root.join("payload.secret");
    std::fs::write(&secret, SECRET).unwrap();
    let mut cmd = xtask(root);
    cmd.arg("seal")
        .args(["--product", product, "--version", "1.0.0"])
        .arg("--in")
        .arg(&input)
        .arg("--out")
        .arg(root.join("out"))
        .args(extra)
        .env("KEYSTONE_PAYLOAD_SECRET_FILE", &secret);
    if let Some(epoch) = epoch {
        cmd.env("KEYSTONE_PAYLOAD_EPOCH", epoch);
    }
    cmd.output().unwrap()
}

fn paths(root: &Path) -> ArtifactPaths {
    ArtifactPaths::new(root.join("out"), "prod", "1.0.0").unwrap()
}

fn open(blob: &[u8], epoch: u32) -> keystone_core::Result<zeroize::Zeroizing<Vec<u8>>> {
    let prefix: &[u8; SEALED_PREFIX_LEN] = blob[..SEALED_PREFIX_LEN].try_into().unwrap();
    let context = keystone_core::artifact_context("prod", "1.0.0", epoch);
    let key = keystone_core::artifact_key_from_prefix(&SECRET, &context, prefix);
    keystone_core::decrypt_artifact(&key, blob)
}

#[test]
fn seal_writes_artifact_layout_with_both_sidecars() {
    let root = workdir("seal");
    ok(seal(
        &root,
        "prod",
        &["--build-id", "release-2026-09"],
        None,
    ));
    let paths = paths(&root);
    assert_eq!(
        paths.sealed,
        root.join("out").join("prod").join("1.0.0.bin")
    );
    assert!(paths.sealed.is_file());
    assert_eq!(
        std::fs::read_to_string(&paths.sha256).unwrap(),
        sha256_hex(PLAINTEXT),
        "sidecar must hash the plaintext"
    );
    assert_eq!(
        std::fs::read_to_string(&paths.build).unwrap(),
        "release-2026-09"
    );
}

/// Every seal is attributable even when the operator names no build.
#[test]
fn seal_defaults_to_random_build_id() {
    let root = workdir("seal");
    ok(seal(&root, "prod", &[], None));
    let build_id = std::fs::read_to_string(paths(&root).build).unwrap();
    assert_eq!(build_id.len(), 16);
    assert!(build_id.bytes().all(|b| b.is_ascii_hexdigit()));
}

/// The seal/serve contract: the blob opens under the key the server
/// derives from its prefix and `artifact_context`, and under no other.
#[test]
fn sealed_blob_decrypts_under_server_derived_key() {
    let root = workdir("seal");
    ok(seal(&root, "prod", &[], None));
    let blob = std::fs::read(paths(&root).sealed).unwrap();
    assert_eq!(&**open(&blob, 0).unwrap(), PLAINTEXT);

    let prefix: &[u8; SEALED_PREFIX_LEN] = blob[..SEALED_PREFIX_LEN].try_into().unwrap();
    let wrong = keystone_core::artifact_key_from_prefix(&SECRET, b"prod:1.0.0", prefix);
    assert!(keystone_core::decrypt_artifact(&wrong, &blob).is_err());
}

/// Bumping the epoch after a secret rotation retires every older blob.
#[test]
fn seal_binds_payload_epoch() {
    let root = workdir("seal");
    let out = ok(seal(&root, "prod", &[], Some("3")));
    assert!(stdout(&out).contains("epoch 3"));
    let blob = std::fs::read(paths(&root).sealed).unwrap();
    assert_eq!(&**open(&blob, 3).unwrap(), PLAINTEXT);
    assert!(
        open(&blob, 0).is_err(),
        "epoch 0 must not open an epoch-3 blob"
    );
}

#[test]
fn seal_rejects_malformed_epoch() {
    let root = workdir("seal");
    let out = seal(&root, "prod", &[], Some("latest"));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("KEYSTONE_PAYLOAD_EPOCH"));
    assert!(!paths(&root).sealed.exists());
}

#[test]
fn seal_rejects_path_traversal_in_product() {
    let root = workdir("seal");
    let out = seal(&root, "../escape", &[], None);
    assert!(!out.status.success(), "traversal must be refused: {out:?}");
    let escaped: PathBuf = root.join("escape");
    assert!(!escaped.exists(), "wrote outside the payload dir");
}
