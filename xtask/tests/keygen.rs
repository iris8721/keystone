//! `xtask keygen`: 33-byte keyfile (key id || seed) named after the key
//! id, never printed, never silently overwritten.

mod common;

use common::{ok, run, stdout, workdir};
use keystone_core::Issuer;

#[test]
fn keygen_writes_keyfile_named_by_key_id_and_never_prints_seed() {
    let root = workdir("keygen");
    let out = ok(run(&root, &["keygen", "--key-id", "7"]));

    let bytes = std::fs::read(root.join("keystone-7.key")).unwrap();
    assert_eq!(bytes.len(), keystone_core::KEYFILE_LEN);
    let issuer = Issuer::from_keyfile(&bytes).unwrap();
    assert_eq!(issuer.key_id(), 7);

    let text = stdout(&out);
    let pubkey = hex::encode(issuer.verifying_key().to_bytes());
    assert!(text.contains(&pubkey), "pubkey missing: {text}");
    let seed = hex::encode(&bytes[1..]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!text.contains(&seed), "seed leaked into stdout: {text}");
    assert!(!stderr.contains(&seed), "seed leaked into stderr: {stderr}");
}

#[cfg(unix)]
#[test]
fn keygen_keyfile_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let root = workdir("keygen");
    ok(run(&root, &["keygen", "--key-id", "1"]));
    let mode = std::fs::metadata(root.join("keystone-1.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "keyfile mode was {mode:o}");
}

/// Overwriting a keyfile invalidates every client pin: only --force may.
#[test]
fn keygen_refuses_to_clobber_without_force() {
    let root = workdir("keygen");
    let keyfile = root.join("keystone-3.key");
    ok(run(&root, &["keygen", "--key-id", "3"]));
    let original = std::fs::read(&keyfile).unwrap();

    let out = run(&root, &["keygen", "--key-id", "3"]);
    assert!(!out.status.success(), "clobber without --force must fail");
    assert_eq!(std::fs::read(&keyfile).unwrap(), original);

    ok(run(&root, &["keygen", "--key-id", "3", "--force"]));
    assert_ne!(std::fs::read(&keyfile).unwrap(), original);
}

#[test]
fn keygen_key_id_is_bounded_to_u8() {
    let root = workdir("keygen");
    ok(run(&root, &["keygen", "--key-id", "255"]));
    assert_eq!(
        std::fs::read(root.join("keystone-255.key")).unwrap()[0],
        255
    );

    let out = run(&root, &["keygen", "--key-id", "256"]);
    assert!(!out.status.success(), "256 is not a u8");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--key-id"));
    assert!(!root.join("keystone-256.key").exists());
}
