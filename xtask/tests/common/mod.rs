//! Every run gets an isolated `XTASK_ROOT` and no inherited `KEYSTONE_*` env.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Fresh temp root holding an empty xtask.toml (all default paths).
pub fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keystone-xtask-{tag}-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("xtask.toml"), "").unwrap();
    dir
}

pub fn xtask(root: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_xtask"));
    cmd.env("XTASK_ROOT", root);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("KEYSTONE_") {
            cmd.env_remove(name);
        }
    }
    cmd
}

pub fn run(root: &Path, args: &[&str]) -> Output {
    xtask(root).args(args).output().unwrap()
}

#[track_caller]
pub fn ok(out: Output) -> Output {
    assert!(out.status.success(), "xtask failed: {out:?}");
    out
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn cert_der(path: &Path) -> Vec<u8> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    CertificateDer::from_pem_file(path).unwrap().to_vec()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}
