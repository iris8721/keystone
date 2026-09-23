//! Startup wiring: everything the server derives from its environment,
//! and the listener that serves the router over it.
//!
//! The entitlement backend is deliberately not part of [`ServerConfig`]:
//! the `keystone-server` binary picks one from `KEYSTONE_ACCOUNTS` /
//! `./accounts.json` / `KEYSTONE_DEV_SEED`, while embedders bring their
//! own [`EntitlementSource`] and call
//! `ServerConfig::from_env()?.serve(source)`.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chrono::Duration;
use keystone_core::{EntitlementSource, Issuer};
use sha2::{Digest, Sha256};

use crate::downloads::DownloadLog;
use crate::state::{ArtifactHashes, RateLimiter, RateLimits};
use crate::tls::{ALLOW_INSECURE_VAR, PeerCertAcceptor, TransportMode, transport_mode};
use crate::{AppState, SessionStore, build_router};

/// Everything the server derives from `KEYSTONE_*` environment
/// variables. Holds the issuer key and several secrets, so it has no
/// `Debug` impl — nothing here should ever reach a log line.
pub struct ServerConfig {
    /// The signing key behind every envelope (KEYSTONE_KEYFILE /
    /// KEYSTONE_SEED / KEYSTONE_KEY_ID).
    pub issuer: Issuer,
    /// sha256 of KEYSTONE_ADMIN_TOKEN; `None` closes /revoke.
    pub admin_token_hash: Option<[u8; 32]>,
    /// Lease lifetime per grant/renewal.
    pub lease_ttl: Duration,
    /// Bounded tolerance for transient failure.
    pub grace_period: Duration,
    /// KEYSTONE_PAYLOAD_DIR; `None` closes the payload routes.
    pub payload_dir: Option<PathBuf>,
    /// KEYSTONE_PAYLOAD_SECRET / KEYSTONE_PAYLOAD_SECRET_FILE.
    pub payload_secret: Option<[u8; 32]>,
    /// KEYSTONE_PAYLOAD_EPOCH (default 0).
    pub payload_epoch: u32,
    /// Pseudonymous download log, when one could be opened.
    pub downloads: Option<DownloadLog>,
    /// KEYSTONE_WATERMARK_SECRET, falling back to the payload secret.
    pub watermark_secret: Option<[u8; 32]>,
    /// Issuer key ids declared compromised at startup
    /// (KEYSTONE_REVOKED_KEY_IDS). Embedders may replace or extend this
    /// before calling [`ServerConfig::serve`].
    pub revoked_key_ids: BTreeSet<u8>,
    /// Listen address: 0.0.0.0 on KEYSTONE_PORT (default 8443).
    pub addr: SocketAddr,
    /// TLS / mTLS / plain, decided by [`transport_mode`].
    pub transport: TransportMode,
}

impl ServerConfig {
    /// Read the configuration from the environment. Bad values are
    /// returned as `Err` with a message naming the variable; nothing
    /// here exits or panics.
    pub fn from_env() -> Result<Self, String> {
        let issuer = load_issuer()?;

        // sha256 of the operator token, or None — which closes /revoke
        // entirely rather than leaving it open.
        let admin_token_hash = std::env::var("KEYSTONE_ADMIN_TOKEN")
            .ok()
            .map(|t| Sha256::digest(t.as_bytes()).into());
        if admin_token_hash.is_none() {
            tracing::warn!("no KEYSTONE_ADMIN_TOKEN — /revoke is disabled");
        }

        // Where sealed payload blobs live ({product}-{version}.bin), and
        // the secret they're sealed under. Either missing closes the
        // payload routes entirely — they answer 503 rather than pretend
        // artifacts exist.
        let payload_dir = std::env::var_os("KEYSTONE_PAYLOAD_DIR").map(PathBuf::from);
        let payload_secret = load_payload_secret()?;
        if payload_dir.is_none() || payload_secret.is_none() {
            tracing::warn!(
                "no KEYSTONE_PAYLOAD_DIR/KEYSTONE_PAYLOAD_SECRET — /payload routes are disabled"
            );
        }
        // The epoch is a key-derivation input: `xtask seal` must have used
        // the same one, or every artifact answers 422.
        let payload_epoch: u32 = match std::env::var("KEYSTONE_PAYLOAD_EPOCH") {
            Ok(v) => v
                .trim()
                .parse()
                .map_err(|e| format!("KEYSTONE_PAYLOAD_EPOCH must be a u32: {e}"))?,
            Err(_) => 0,
        };

        let revoked_key_ids = load_revoked_key_ids()?;
        if !revoked_key_ids.is_empty() {
            tracing::warn!(?revoked_key_ids, "issuer keys revoked at startup");
        }

        // Pseudonymous download records for leak investigation. The log
        // lives next to the payloads unless KEYSTONE_DOWNLOAD_LOG points
        // elsewhere; no path at all means logging is off, not improvised.
        let download_log_path = std::env::var_os("KEYSTONE_DOWNLOAD_LOG")
            .map(PathBuf::from)
            .or_else(|| payload_dir.as_ref().map(|dir| dir.join("downloads.jsonl")));
        let watermark_secret = load_watermark_secret()?.or(payload_secret);
        let downloads = match (download_log_path, watermark_secret) {
            (Some(path), Some(secret)) => match DownloadLog::open(&path, secret) {
                Ok(log) => Some(log),
                Err(e) => {
                    tracing::warn!(path = %path.display(), "cannot open download log: {e} — logging disabled");
                    None
                }
            },
            (Some(_), None) => {
                tracing::warn!(
                    "download log configured but no KEYSTONE_WATERMARK_SECRET/payload secret — logging disabled"
                );
                None
            }
            (None, _) => {
                tracing::warn!(
                    "no KEYSTONE_DOWNLOAD_LOG or payload dir — download logging disabled"
                );
                None
            }
        };

        let port: u16 = std::env::var("KEYSTONE_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8443);
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        // TLS with client certs is the only production transport. Plain
        // HTTP and TLS-without-mTLS are refused unless KEYSTONE_ALLOW_INSECURE
        // is exactly "1" — the decision itself lives in `transport_mode`.
        let is_insecure_allowed = std::env::var(ALLOW_INSECURE_VAR).as_deref() == Ok("1");
        let transport = transport_mode(
            std::env::var_os("KEYSTONE_TLS_CERT").map(PathBuf::from),
            std::env::var_os("KEYSTONE_TLS_KEY").map(PathBuf::from),
            std::env::var_os("KEYSTONE_CA_CERT").map(PathBuf::from),
            is_insecure_allowed,
        )?;

        Ok(Self {
            issuer,
            admin_token_hash,
            lease_ttl: Duration::seconds(300),
            grace_period: Duration::seconds(60),
            payload_dir,
            payload_secret,
            payload_epoch,
            downloads,
            watermark_secret,
            revoked_key_ids,
            addr,
            transport,
        })
    }

    /// Build the router state around `entitlements` and serve until the
    /// listener fails. Returns `Err` when the TLS material cannot be
    /// read or loaded, the address cannot be bound, or the server stops
    /// with an error.
    pub async fn serve(self, entitlements: Arc<dyn EntitlementSource>) -> Result<(), String> {
        let addr = self.addr;
        let state = AppState {
            issuer: Arc::new(self.issuer),
            store: SessionStore::new(),
            entitlements,
            admin_token_hash: self.admin_token_hash,
            lease_ttl: self.lease_ttl,
            grace_period: self.grace_period,
            payload_dir: self.payload_dir,
            payload_secret: self.payload_secret,
            payload_epoch: self.payload_epoch,
            downloads: self.downloads,
            watermark_secret: self.watermark_secret,
            rate_limits: RateLimits::default(),
            rate_limiter: Arc::new(RateLimiter::new()),
            artifact_hashes: Arc::new(ArtifactHashes::new()),
            revoked_key_ids: Arc::new(RwLock::new(self.revoked_key_ids)),
        };

        match self.transport {
            TransportMode::MutualTls { cert, key, ca } => {
                let ca_pem = read_pem("KEYSTONE_CA_CERT", &ca)?;
                let cert_pem = read_pem("KEYSTONE_TLS_CERT", &cert)?;
                let key_pem = read_pem("KEYSTONE_TLS_KEY", &key)?;
                let config = crate::tls::load_rustls_config(&cert_pem, &key_pem, Some(&ca_pem))
                    .map_err(|e| format!("loading KEYSTONE_TLS_CERT/KEYSTONE_TLS_KEY: {e}"))?;
                tracing::info!(%addr, "keystone-server listening (TLS, client certs required)");
                serve_tls(addr, config, state).await
            }
            TransportMode::TlsOnly { cert, key } => {
                let cert_pem = read_pem("KEYSTONE_TLS_CERT", &cert)?;
                let key_pem = read_pem("KEYSTONE_TLS_KEY", &key)?;
                let config = crate::tls::load_rustls_config(&cert_pem, &key_pem, None)
                    .map_err(|e| format!("loading KEYSTONE_TLS_CERT/KEYSTONE_TLS_KEY: {e}"))?;
                tracing::warn!(
                    %addr,
                    "{ALLOW_INSECURE_VAR}=1: listening (TLS) WITHOUT client certs — cert_sha256 bindings cannot be enforced"
                );
                serve_tls(addr, config, state).await
            }
            TransportMode::Plain => {
                let listener = tokio::net::TcpListener::bind(addr)
                    .await
                    .map_err(|e| format!("bind keystone-server {addr}: {e}"))?;
                tracing::warn!(
                    %addr,
                    "{ALLOW_INSECURE_VAR}=1: listening WITHOUT TLS — real clients require https and will refuse"
                );
                axum::serve(
                    listener,
                    build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .map_err(|e| format!("keystone-server failed: {e}"))
            }
        }
    }
}

/// Load the issuer's 32-byte ed25519 seed and its key id.
///
/// KEYSTONE_KEYFILE — path to a file holding the raw 32-byte seed.
/// KEYSTONE_SEED    — the seed as a 64-char hex string.
/// KEYSTONE_KEY_ID  — the u8 id clients look this key up by
///                      (default 1). Rotate by shipping the new key
///                      under a new id, then revoking the old one.
/// Neither seed set — ephemeral key + warning. Fine for development;
///                      every signature dies with the process, which is
///                      exactly what a missing key should mean.
fn load_issuer() -> Result<Issuer, String> {
    let key_id: u8 = match std::env::var("KEYSTONE_KEY_ID") {
        Ok(v) => v
            .trim()
            .parse()
            .map_err(|e| format!("KEYSTONE_KEY_ID must be a u8: {e}"))?,
        Err(_) => 1,
    };
    if let Ok(path) = std::env::var("KEYSTONE_KEYFILE") {
        let seed = read_secret_file("KEYSTONE_KEYFILE", &path)?;
        return Ok(Issuer::from_seed(&seed, key_id));
    }
    if let Ok(hex_seed) = std::env::var("KEYSTONE_SEED") {
        let seed = decode_hex_secret("KEYSTONE_SEED", &hex_seed)?;
        return Ok(Issuer::from_seed(&seed, key_id));
    }
    tracing::warn!(
        "no KEYSTONE_KEYFILE or KEYSTONE_SEED — ephemeral issuer key; \
         all signatures die with this process"
    );
    Ok(Issuer::generate_with_id(key_id))
}

/// Issuer key ids declared compromised at startup:
/// KEYSTONE_REVOKED_KEY_IDS as comma-separated u8s (default empty).
/// Clients learn them from every grant body and stop trusting those
/// keys — the README answer to a key leaking in a build.
fn load_revoked_key_ids() -> Result<BTreeSet<u8>, String> {
    let Ok(list) = std::env::var("KEYSTONE_REVOKED_KEY_IDS") else {
        return Ok(BTreeSet::new());
    };
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u8>()
                .map_err(|_| format!("KEYSTONE_REVOKED_KEY_IDS: {s:?} is not a u8"))
        })
        .collect()
}

/// Load the 32-byte artifact secret the payload blobs are sealed under.
///
/// KEYSTONE_PAYLOAD_SECRET      — the secret as a 64-char hex string.
/// KEYSTONE_PAYLOAD_SECRET_FILE — path to a file holding the raw 32 bytes.
/// Neither set                  — payload routes stay closed (503); the
///                                server still runs, it just can't
///                                attest artifacts it can't unseal.
fn load_payload_secret() -> Result<Option<[u8; 32]>, String> {
    if let Ok(path) = std::env::var("KEYSTONE_PAYLOAD_SECRET_FILE") {
        return read_secret_file("KEYSTONE_PAYLOAD_SECRET_FILE", &path).map(Some);
    }
    if let Ok(hex_secret) = std::env::var("KEYSTONE_PAYLOAD_SECRET") {
        return decode_hex_secret("KEYSTONE_PAYLOAD_SECRET", &hex_secret).map(Some);
    }
    Ok(None)
}

/// Load the 32-byte secret that pseudonymizes accounts in the download
/// log. KEYSTONE_WATERMARK_SECRET (64-char hex) when set; otherwise the
/// payload secret doubles as the pseudonym key — one less secret to
/// provision, and the log stays attributable to whoever holds the
/// server's secrets either way.
fn load_watermark_secret() -> Result<Option<[u8; 32]>, String> {
    match std::env::var("KEYSTONE_WATERMARK_SECRET") {
        Ok(hex_secret) => decode_hex_secret("KEYSTONE_WATERMARK_SECRET", &hex_secret).map(Some),
        Err(_) => Ok(None),
    }
}

/// Read a file that must hold exactly 32 raw secret bytes; `var` names
/// the environment variable that pointed at it.
fn read_secret_file(var: &str, path: &str) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{var} {path}: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{var} must contain exactly 32 bytes"))
}

/// Decode a hex environment value that must yield exactly 32 bytes.
fn decode_hex_secret(var: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value.trim()).map_err(|e| format!("{var} must be hex: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{var} must decode to exactly 32 bytes"))
}

/// Read TLS material named by `var`.
fn read_pem(var: &str, path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("reading {var} {}: {e}", path.display()))
}

/// PeerCertAcceptor, not bind_rustls: handlers need the peer's
/// certificate chain for the cert_sha256 session binding, and
/// axum-server's stock acceptor discards it.
async fn serve_tls(
    addr: SocketAddr,
    config: axum_server::tls_rustls::RustlsConfig,
    state: AppState,
) -> Result<(), String> {
    axum_server::Server::bind(addr)
        .acceptor(PeerCertAcceptor::new(config))
        .serve(build_router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| format!("keystone-server failed: {e}"))
}
