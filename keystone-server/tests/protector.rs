//! Protector integration: per-fetch mutation, watermarking, cache
//! supersession and refusal semantics, download records, and the
//! untouched unconfigured path.
//!
//! The fake protector copies its input to its output and appends the
//! fixed suffix `KEYSTONE` — deterministic, so every byte-level difference
//! between two fetches comes from the per-download watermark.

mod common;

use std::path::{Path, PathBuf};

use axum::http::StatusCode;
use chrono::Utc;
use common::*;
use keystone_core::wire::ErrorCode;
use keystone_core::{
    ArtifactPaths, decrypt_artifact, derive_watermark_secret, seal_artifact, unwrap_artifact_key,
};
use keystone_server::{PayloadConfig, ProtectorConfig, watermark_bytes};
use sha2::{Digest, Sha256};

const VERSION: &str = "3.1.4";
const PAYLOAD_SECRET: [u8; 32] = [0x42; 32];
const EPOCH: u32 = 3;
const PATTERN: &[u8] = b"WATERMARK_SLOT16";
const PLAINTEXT: &[u8] = b"the application bytes WATERMARK_SLOT16 and nothing else";
const PLAINTEXT_BARE: &[u8] = b"the application bytes without any reserved region";
const SUFFIX: &[u8] = b"KEYSTONE";

fn seal_release(dir: &Path, product: &str, version: &str, plaintext: &[u8]) -> ArtifactPaths {
    let paths = ArtifactPaths::new(dir, product, version).unwrap();
    std::fs::create_dir_all(paths.sealed.parent().unwrap()).unwrap();
    let context = keystone_core::artifact_context(product, version, EPOCH);
    std::fs::write(
        &paths.sealed,
        seal_artifact(&PAYLOAD_SECRET, &context, plaintext).unwrap(),
    )
    .unwrap();
    std::fs::write(&paths.sha256, hex::encode(Sha256::digest(plaintext))).unwrap();
    std::fs::write(&paths.build, format!("build-{product}-{version}\n")).unwrap();
    paths
}

/// A protector that copies input to output and appends a fixed suffix.
fn fake_protector(dir: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let path = dir.join("fake-protector.ps1");
        std::fs::write(
            &path,
            concat!(
                "param([Parameter(Mandatory=$true)][string]$In, ",
                "[Parameter(Mandatory=$true)][string]$Out, ",
                "[Parameter(Mandatory=$true)][string]$Passes)\n",
                "$ErrorActionPreference = 'Stop'\n",
                "$d = [IO.File]::ReadAllBytes($In)\n",
                "$s = [byte[]](0x4B,0x45,0x59,0x53,0x54,0x4F,0x4E,0x45)\n",
                "$m = New-Object byte[] ($d.Length + $s.Length)\n",
                "[Array]::Copy($d, $m, $d.Length)\n",
                "[Array]::Copy($s, 0, $m, $d.Length, $s.Length)\n",
                "[IO.File]::WriteAllBytes($Out, $m)\n",
            ),
        )
        .unwrap();
        path
    }
    #[cfg(not(windows))]
    {
        let path = dir.join("fake-protector.sh");
        std::fs::write(
            &path,
            concat!(
                "#!/bin/sh\n",
                "in=\nout=\n",
                "while [ $# -gt 0 ]; do\n",
                "  case \"$1\" in\n",
                "    -In) in=\"$2\" ;;\n",
                "    -Out) out=\"$2\" ;;\n",
                "  esac\n",
                "  shift 2\n",
                "done\n",
                "cp \"$in\" \"$out\"\n",
                "printf 'KEYSTONE' >> \"$out\"\n",
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

struct Rig {
    h: Harness,
    stored: Vec<u8>,
}

async fn rig(plaintext: &[u8], watermark: bool, log: Option<PathBuf>) -> Rig {
    let dir = temp_dir("protector");
    let paths = seal_release(&dir, PRODUCT, VERSION, plaintext);
    let script = fake_protector(&dir);
    let payloads =
        PayloadConfig::new(&dir, PAYLOAD_SECRET, EPOCH).with_protector(ProtectorConfig {
            script,
            watermark_pattern: watermark.then(|| PATTERN.to_vec()),
        });
    let h = harness_with(TestSource::standard(), |b| {
        let b = b.payloads(payloads);
        match log {
            Some(path) => b.download_log(path),
            None => b,
        }
    })
    .await;
    Rig {
        h,
        stored: std::fs::read(&paths.sealed).unwrap(),
    }
}

fn pattern_offset() -> usize {
    PLAINTEXT
        .windows(PATTERN.len())
        .position(|w| w == PATTERN)
        .expect("pattern is in the plaintext")
}

async fn fetch(h: &Harness, session: &Session) -> (keystone_core::Manifest, [u8; 32]) {
    let req = payload_req(session, PRODUCT, VERSION);
    let (status, value) = post(&h.app, "/payload", &req).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    let body = open_payload(&h.issuers, &value, &req);
    let manifest = body
        .manifest
        .verify(&h.issuers, Utc::now())
        .unwrap()
        .clone();
    let key = *unwrap_artifact_key(&session.key, &req.nonce, &body.payload_key_wrap).unwrap();
    (manifest, key)
}

async fn download(h: &Harness, session: &Session) -> (StatusCode, Vec<u8>) {
    get(
        &h.app,
        &format!("/payload/{PRODUCT}/{VERSION}"),
        Some(&download_auth(session, PRODUCT, VERSION)),
    )
    .await
}

#[tokio::test]
async fn manifest_attests_exactly_the_served_mutated_bytes() {
    let Rig { h, stored } = rig(PLAINTEXT, true, None).await;
    let session = exchange(&h).await;
    let (manifest, key) = fetch(&h, &session).await;

    let (status, sealed) = download(&h, &session).await;
    assert_eq!(status, StatusCode::OK);
    // the served blob is not the stored one
    assert_ne!(sealed, stored);
    let plaintext = decrypt_artifact(&key, &sealed).unwrap();
    manifest.verify_payload(&plaintext).unwrap();
    // the protector ran (suffix) and the watermark sits at the pattern slot
    assert_eq!(&plaintext[plaintext.len() - SUFFIX.len()..], SUFFIX);
    let expected = watermark_bytes(
        &derive_watermark_secret(&PAYLOAD_SECRET),
        &manifest.download_id,
        PATTERN.len(),
    );
    let at = pattern_offset();
    assert_eq!(&plaintext[at..at + PATTERN.len()], &expected[..]);
}

#[tokio::test]
async fn two_fetches_differ_and_the_latest_supersedes() {
    let Rig { h, .. } = rig(PLAINTEXT, true, None).await;
    let session = exchange(&h).await;
    let (a, key) = fetch(&h, &session).await;
    let (b, _) = fetch(&h, &session).await;
    assert_ne!(a.sha256, b.sha256);
    assert_ne!(a.download_id, b.download_id);

    // the download serves exactly what the latest manifest attests
    let (status, sealed) = download(&h, &session).await;
    assert_eq!(status, StatusCode::OK);
    let plaintext = decrypt_artifact(&key, &sealed).unwrap();
    b.verify_payload(&plaintext).unwrap();
    assert!(a.verify_payload(&plaintext).is_err());
}

#[tokio::test]
async fn download_is_single_shot() {
    let Rig { h, .. } = rig(PLAINTEXT, true, None).await;
    let session = exchange(&h).await;
    fetch(&h, &session).await;
    assert_eq!(download(&h, &session).await.0, StatusCode::OK);
    let (status, bytes) = download(&h, &session).await;
    assert_eq!(
        (status, code_bytes(&bytes)),
        (StatusCode::NOT_FOUND, ErrorCode::ArtifactNotFound)
    );
}

#[tokio::test]
async fn download_without_fetch_is_refused() {
    let Rig { h, stored, .. } = rig(PLAINTEXT, true, None).await;
    let session = exchange(&h).await;
    let (status, bytes) = download(&h, &session).await;
    assert_eq!(
        (status, code_bytes(&bytes)),
        (StatusCode::NOT_FOUND, ErrorCode::ArtifactNotFound)
    );
    // the stored, unmutated artifact is never served in its place
    assert_ne!(bytes, stored);
}

#[tokio::test]
async fn absent_pattern_skips_the_watermark_but_not_the_protector() {
    let Rig { h, .. } = rig(PLAINTEXT_BARE, true, None).await;
    let session = exchange(&h).await;
    let (manifest, key) = fetch(&h, &session).await;
    let (_, sealed) = download(&h, &session).await;
    let plaintext = decrypt_artifact(&key, &sealed).unwrap();
    manifest.verify_payload(&plaintext).unwrap();
    // mutated (suffix present) but the bare bytes are untouched
    assert_eq!(&plaintext[..PLAINTEXT_BARE.len()], PLAINTEXT_BARE);
    assert_ne!(manifest.sha256, Sha256::digest(PLAINTEXT_BARE).as_slice());
}

#[tokio::test]
async fn mutated_downloads_are_logged_with_sha_and_watermark_flag() {
    let log_dir = temp_dir("protector-log");
    let log = log_dir.join("downloads.jsonl");
    let Rig { h, .. } = rig(PLAINTEXT, true, Some(log.clone())).await;
    let session = exchange(&h).await;
    let (manifest, _) = fetch(&h, &session).await;
    assert_eq!(download(&h, &session).await.0, StatusCode::OK);

    let lines = wait_for_lines(&log, 2).await;
    assert_eq!(lines[0]["route"], "manifest_issued");
    assert_eq!(lines[1]["route"], "blob_served");
    for line in &lines {
        assert_eq!(line["watermarked"], true);
        assert_eq!(line["mutated_sha256"], hex::encode(manifest.sha256));
    }
}

#[tokio::test]
async fn unwatermarked_downloads_log_the_flag_false() {
    let log_dir = temp_dir("protector-log-bare");
    let log = log_dir.join("downloads.jsonl");
    let Rig { h, .. } = rig(PLAINTEXT_BARE, true, Some(log.clone())).await;
    let session = exchange(&h).await;
    fetch(&h, &session).await;
    assert_eq!(download(&h, &session).await.0, StatusCode::OK);
    let lines = wait_for_lines(&log, 2).await;
    for line in &lines {
        assert_eq!(line["watermarked"], false);
        assert!(line["mutated_sha256"].is_string());
    }
}

#[tokio::test]
async fn without_a_protector_the_stored_bytes_are_served_unchanged() {
    let dir = temp_dir("protector-off");
    let paths = seal_release(&dir, PRODUCT, VERSION, PLAINTEXT);
    let payloads = PayloadConfig::new(&dir, PAYLOAD_SECRET, EPOCH);
    let h = harness_with(TestSource::standard(), |b| b.payloads(payloads)).await;
    let session = exchange(&h).await;
    let (manifest, key) = fetch(&h, &session).await;
    assert_eq!(manifest.sha256, Sha256::digest(PLAINTEXT).as_slice());
    let (status, sealed) = download(&h, &session).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sealed, std::fs::read(&paths.sealed).unwrap());
    assert_eq!(
        decrypt_artifact(&key, &sealed).unwrap().as_slice(),
        PLAINTEXT
    );
}

async fn wait_for_lines(path: &Path, count: usize) -> Vec<serde_json::Value> {
    for _ in 0..200 {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        if lines.len() >= count {
            return lines;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("download log never reached {count} lines");
}
