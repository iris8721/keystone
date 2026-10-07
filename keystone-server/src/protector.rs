//! Per-download artifact mutation.
//!
//! When a protector is configured, `POST /payload` decrypts the stored
//! artifact, optionally patches a watermark region derived from the
//! download id, runs the external protector over the plaintext, and
//! re-seals the mutated bytes under the very artifact key it wrapped for
//! the client — so the wrapped key, the served blob, and the manifest's
//! sha256 all describe the same mutated plaintext.
//!
//! The sealed mutated artifact waits in a bounded per-session cache until
//! `GET /payload/{product}/{version}` pops it. The stored, unmutated
//! artifact is never served to a session whose manifest attests mutated
//! bytes.

use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;

use chrono::{DateTime, Utc};
use keystone_core::fs::write_owner_only_atomic;
use keystone_core::{decrypt_artifact, seal_under};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::{PayloadConfig, ProtectorConfig};
use crate::routes::common::{ApiError, artifact_invalid};

/// Sealed mutated artifacts that may await download at once. Each is at
/// most [`keystone_core::MAX_ARTIFACT_BYTES`].
const CACHE_CAPACITY: usize = 64;
/// Ceiling on one protector run. The wrapper documents ~0.25 s for light
/// passes; a protector that hangs must not hang the fetch with it.
const PROTECTOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// One fetch's mutated artifact: what the manifest attests and the
/// download route serves.
pub(crate) struct Mutation {
    /// Mutated plaintext, sealed under the artifact key the client holds.
    pub sealed: Vec<u8>,
    /// sha256 of the mutated plaintext; the manifest carries this.
    pub sha256: [u8; 32],
    /// Whether the watermark pattern was found and patched.
    pub watermarked: bool,
    /// Release build id, kept for the download record.
    pub build_id: String,
}

/// A [`Mutation`] plus the instant its manifest dies.
pub(crate) struct CachedMutation {
    pub mutation: Mutation,
    pub expires_at: DateTime<Utc>,
}

/// Bounded map from session to the artifact its last fetch attested. A
/// second fetch supersedes the first; a download pops. TTL is the manifest
/// expiry, so an entry never outlives the manifest that attests it.
#[derive(Default)]
pub(crate) struct MutationCache {
    entries: Mutex<HashMap<Uuid, CachedMutation>>,
}

impl MutationCache {
    /// Store `mutation` for `session_id` until `expires_at`, superseding
    /// any earlier fetch. At capacity, expired entries go first, then the
    /// one expiring soonest.
    pub(crate) fn insert(&self, session_id: Uuid, mutation: Mutation, expires_at: DateTime<Utc>) {
        let mut entries = self.entries.lock();
        let now = Utc::now();
        entries.retain(|_, cached| now < cached.expires_at);
        if entries.len() >= CACHE_CAPACITY
            && !entries.contains_key(&session_id)
            && let Some(victim) = entries
                .iter()
                .min_by_key(|(_, cached)| cached.expires_at)
                .map(|(id, _)| *id)
        {
            entries.remove(&victim);
        }
        entries.insert(
            session_id,
            CachedMutation {
                mutation,
                expires_at,
            },
        );
    }

    /// Take the session's artifact; `None` when it was never fetched,
    /// superseded, already downloaded, or expired.
    pub(crate) fn pop(&self, session_id: &Uuid, now: DateTime<Utc>) -> Option<Mutation> {
        match self.entries.lock().remove(session_id) {
            Some(cached) if now < cached.expires_at => Some(cached.mutation),
            _ => None,
        }
    }

    /// Drop expired entries (the sweep timer calls this).
    pub(crate) fn sweep(&self, now: DateTime<Utc>) {
        self.entries
            .lock()
            .retain(|_, cached| now < cached.expires_at);
    }
}

/// Deterministic watermark bytes for one download: HMAC-SHA256 blocks
/// keyed by the watermark secret over the download id, truncated to the
/// pattern length. Given a suspect download's id, an operator recomputes
/// these bytes and matches them against the patched region. Alias for
/// [`keystone_core::watermark::tag_bytes`]; every patched site in a
/// download holds this same tag.
pub fn watermark_bytes(secret: &[u8; 32], download_id: &str, len: usize) -> Vec<u8> {
    keystone_core::watermark::tag_bytes(secret, download_id, len)
}

/// Decrypt the stored artifact, watermark it when the configured pattern
/// is present, run the protector, and re-seal the mutated plaintext under
/// the same artifact key the session was wrapped.
pub(crate) async fn mutate(
    payloads: &PayloadConfig,
    protector: &ProtectorConfig,
    artifact_key: &Zeroizing<[u8; 32]>,
    sealed: &[u8],
    build_id: &str,
    download_id: &str,
) -> Result<Mutation, ApiError> {
    let (plaintext, watermarked) =
        watermark(payloads, protector, artifact_key, sealed, download_id).await?;
    let mutated = run_protector(protector, &plaintext).await?;
    let sha256: [u8; 32] = Sha256::digest(&mutated).into();
    let sealed = seal_under(artifact_key, &mutated)
        .map_err(|_| artifact_invalid("mutated artifact exceeds the seal cap"))?;
    Ok(Mutation {
        sealed,
        sha256,
        watermarked,
        build_id: build_id.to_string(),
    })
}

/// Decrypt under the fetched key and patch a per-download subset of the
/// pattern's occurrences with the download's tag. Zero occurrences skips
/// the watermark (the protector still runs) and says so; exactly one is
/// the legacy single-site patch; two or more selects up to
/// `watermark_sites` offsets via [`keystone_core::watermark::apply`].
async fn watermark(
    payloads: &PayloadConfig,
    protector: &ProtectorConfig,
    artifact_key: &Zeroizing<[u8; 32]>,
    sealed: &[u8],
    download_id: &str,
) -> Result<(Zeroizing<Vec<u8>>, bool), ApiError> {
    let key: [u8; 32] = **artifact_key;
    let sealed = sealed.to_vec();
    let watermark_secret = *payloads.watermark_secret;
    let download_id = download_id.to_string();
    let pattern = protector.watermark_pattern.clone();
    let sites = protector.watermark_sites;
    let plaintext = tokio::task::spawn_blocking(move || {
        use keystone_core::watermark::PatchOutcome;
        let mut plaintext = decrypt_artifact(&key, &sealed)
            .map_err(|_| "stored artifact does not open under its key")?;
        let Some(pattern) = &pattern else {
            return Ok::<_, &'static str>((plaintext, false));
        };
        match keystone_core::watermark::apply(
            &mut plaintext,
            pattern,
            &watermark_secret,
            &download_id,
            sites,
        ) {
            PatchOutcome::NotFound => Ok((plaintext, false)),
            PatchOutcome::SingleSite => {
                tracing::debug!("one watermark pattern occurrence; legacy single-site patch");
                Ok((plaintext, true))
            }
            PatchOutcome::MultiSite {
                patched,
                candidates,
            } => {
                tracing::debug!(
                    patched,
                    candidates,
                    "watermarked a per-download subset of pattern sites"
                );
                Ok((plaintext, true))
            }
        }
    })
    .await
    .map_err(|e| artifact_invalid(format!("watermark task: {e}")))?
    .map_err(artifact_invalid)?;
    if protector.watermark_pattern.is_some() && !plaintext.1 {
        tracing::info!("watermark pattern not found; artifact served unwatermarked");
    }
    Ok(plaintext)
}

/// Run the protector over `plaintext` in a private temp directory that is
/// removed on every path, and return the mutated bytes.
async fn run_protector(
    protector: &ProtectorConfig,
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let dir = std::env::temp_dir().join(format!("keystone-mutate-{}", Uuid::new_v4()));
    tokio::fs::create_dir(&dir)
        .await
        .map_err(|e| artifact_invalid(format!("creating temp dir: {e}")))?;
    let outcome = protector_pass(protector, &dir, plaintext).await;
    let _ = tokio::fs::remove_dir_all(&dir).await;
    outcome
}

async fn protector_pass(
    protector: &ProtectorConfig,
    dir: &Path,
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let input = dir.join("in.bin");
    let output = dir.join("out.bin");
    let to_write = input.clone();
    let bytes = plaintext.to_vec();
    tokio::task::spawn_blocking(move || write_owner_only_atomic(&to_write, &bytes))
        .await
        .map_err(|e| artifact_invalid(format!("plaintext write task: {e}")))?
        .map_err(|e| artifact_invalid(format!("writing plaintext: {e}")))?;

    let status = tokio::time::timeout(
        PROTECTOR_TIMEOUT,
        protector_command(&protector.script, &input, &output).output(),
    )
    .await;
    match status {
        Ok(Ok(out)) if out.status.success() => {}
        Ok(Ok(out)) => {
            return Err(artifact_invalid(format!(
                "protector exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(Err(e)) => return Err(artifact_invalid(format!("spawning protector: {e}"))),
        Err(_) => return Err(artifact_invalid("protector timed out")),
    }

    let mutated = tokio::fs::read(&output)
        .await
        .map_err(|e| artifact_invalid(format!("reading protector output: {e}")))?;
    if mutated.is_empty() {
        return Err(artifact_invalid("protector produced an empty artifact"));
    }
    Ok(Zeroizing::new(mutated))
}

/// The protector invocation: `script -In <in> -Out <out> -Passes light`.
/// PowerShell scripts run through the shell (Windows PowerShell on
/// Windows, pwsh elsewhere); anything else executes directly.
fn protector_command(script: &Path, input: &Path, output: &Path) -> Command {
    let mut cmd = if script.extension().is_some_and(|ext| ext == "ps1") {
        let shell = if cfg!(windows) { "powershell" } else { "pwsh" };
        let mut cmd = Command::new(shell);
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
        ])
        .arg("-File")
        .arg(script);
        cmd
    } else {
        Command::new(script)
    };
    cmd.arg("-In")
        .arg(input)
        .arg("-Out")
        .arg(output)
        .arg("-Passes")
        .arg("light")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn mutation(sealed: Vec<u8>) -> Mutation {
        Mutation {
            sealed,
            sha256: [0u8; 32],
            watermarked: false,
            build_id: "build".into(),
        }
    }

    #[test]
    fn watermark_bytes_are_deterministic_per_download_and_fill_any_length() {
        let a = watermark_bytes(&[1u8; 32], "abc", 16);
        let b = watermark_bytes(&[1u8; 32], "abc", 16);
        let c = watermark_bytes(&[1u8; 32], "abd", 16);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
        let long = watermark_bytes(&[1u8; 32], "abc", 100);
        assert_eq!(long.len(), 100);
        assert_eq!(&long[..16], &a[..]);
        // Keyed: another secret yields other bytes.
        assert_ne!(watermark_bytes(&[2u8; 32], "abc", 16), a);
    }

    #[test]
    fn cache_supersedes_and_pops_once() {
        let cache = MutationCache::default();
        let id = Uuid::new_v4();
        let now = Utc::now();
        cache.insert(id, mutation(vec![1]), now + Duration::seconds(60));
        cache.insert(id, mutation(vec![2]), now + Duration::seconds(60));
        let popped = cache.pop(&id, now).unwrap();
        assert_eq!(popped.sealed, vec![2]);
        assert!(cache.pop(&id, now).is_none());
    }

    #[test]
    fn expired_entries_are_not_served() {
        let cache = MutationCache::default();
        let id = Uuid::new_v4();
        let now = Utc::now();
        cache.insert(id, mutation(vec![1]), now);
        assert!(cache.pop(&id, now).is_none());
    }

    #[test]
    fn full_cache_evicts_the_entry_expiring_soonest() {
        let cache = MutationCache::default();
        let now = Utc::now();
        let first = Uuid::new_v4();
        cache.insert(first, mutation(vec![1]), now + Duration::seconds(10));
        for _ in 1..CACHE_CAPACITY {
            cache.insert(
                Uuid::new_v4(),
                mutation(vec![2]),
                now + Duration::seconds(60),
            );
        }
        let newcomer = Uuid::new_v4();
        cache.insert(newcomer, mutation(vec![3]), now + Duration::seconds(30));
        // `first` expired soonest and gave way; the newcomer survived.
        assert!(cache.pop(&first, now).is_none());
        assert_eq!(cache.pop(&newcomer, now).unwrap().sealed, vec![3]);
    }
}
