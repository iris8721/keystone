//! keystone-server entry point: load the issuer key, build state, serve.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::process::exit;
use std::sync::{Arc, RwLock};

use chrono::Duration;
use keystone_core::Issuer;
use keystone_server::downloads::DownloadLog;
use keystone_server::entitlement::dev_seed_source;
use keystone_server::state::{ArtifactHashes, RateLimiter, RateLimits};
use keystone_server::tls::{ALLOW_INSECURE_VAR, TransportMode, transport_mode};
use keystone_server::{AppState, SessionStore, build_router};
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;

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
fn load_issuer() -> Issuer {
    let key_id: u8 = std::env::var("KEYSTONE_KEY_ID")
        .ok()
        .map(|v| v.trim().parse().expect("KEYSTONE_KEY_ID must be a u8"))
        .unwrap_or(1);
    if let Ok(path) = std::env::var("KEYSTONE_KEYFILE") {
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("KEYSTONE_KEYFILE {path}: {e}"));
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .expect("KEYSTONE_KEYFILE must contain exactly 32 bytes");
        return Issuer::from_seed(&seed, key_id);
    }
    if let Ok(hex_seed) = std::env::var("KEYSTONE_SEED") {
        let bytes = hex::decode(hex_seed.trim()).expect("KEYSTONE_SEED must be hex");
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .expect("KEYSTONE_SEED must decode to exactly 32 bytes");
        return Issuer::from_seed(&seed, key_id);
    }
    tracing::warn!(
        "no KEYSTONE_KEYFILE or KEYSTONE_SEED — ephemeral issuer key; \
         all signatures die with this process"
    );
    Issuer::generate_with_id(key_id)
}

/// Issuer key ids declared compromised at startup:
/// KEYSTONE_REVOKED_KEY_IDS as comma-separated u8s (default empty).
/// Clients learn them from every grant body and stop trusting those
/// keys — the README answer to a key leaking in a build.
fn load_revoked_key_ids() -> BTreeSet<u8> {
    std::env::var("KEYSTONE_REVOKED_KEY_IDS")
        .ok()
        .map(|list| {
            list.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.parse::<u8>()
                        .unwrap_or_else(|_| panic!("KEYSTONE_REVOKED_KEY_IDS: {s:?} is not a u8"))
                })
                .collect::<BTreeSet<u8>>()
        })
        .unwrap_or_default()
}

/// Load the 32-byte artifact secret the payload blobs are sealed under.
///
/// KEYSTONE_PAYLOAD_SECRET      — the secret as a 64-char hex string.
/// KEYSTONE_PAYLOAD_SECRET_FILE — path to a file holding the raw 32 bytes.
/// Neither set                  — payload routes stay closed (503); the
///                                server still runs, it just can't
///                                attest artifacts it can't unseal.
fn load_payload_secret() -> Option<[u8; 32]> {
    if let Ok(path) = std::env::var("KEYSTONE_PAYLOAD_SECRET_FILE") {
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("KEYSTONE_PAYLOAD_SECRET_FILE {path}: {e}"));
        return Some(
            bytes
                .as_slice()
                .try_into()
                .expect("KEYSTONE_PAYLOAD_SECRET_FILE must contain exactly 32 bytes"),
        );
    }
    if let Ok(hex_secret) = std::env::var("KEYSTONE_PAYLOAD_SECRET") {
        let bytes = hex::decode(hex_secret.trim()).expect("KEYSTONE_PAYLOAD_SECRET must be hex");
        return Some(
            bytes
                .as_slice()
                .try_into()
                .expect("KEYSTONE_PAYLOAD_SECRET must decode to exactly 32 bytes"),
        );
    }
    None
}

/// Load the 32-byte secret that pseudonymizes accounts in the download
/// log. KEYSTONE_WATERMARK_SECRET (64-char hex) when set; otherwise the
/// payload secret doubles as the pseudonym key — one less secret to
/// provision, and the log stays attributable to whoever holds the
/// server's secrets either way.
fn load_watermark_secret() -> Option<[u8; 32]> {
    let hex_secret = std::env::var("KEYSTONE_WATERMARK_SECRET").ok()?;
    let bytes = hex::decode(hex_secret.trim()).expect("KEYSTONE_WATERMARK_SECRET must be hex");
    Some(
        bytes
            .as_slice()
            .try_into()
            .expect("KEYSTONE_WATERMARK_SECRET must decode to exactly 32 bytes"),
    )
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let issuer = load_issuer();
    // Entitlement backend selection, in precedence order:
    //   1. KEYSTONE_ACCOUNTS set → the file must exist; a configured
    //      path that isn't there is a misconfiguration (bad mount,
    //      wrong env), not a reason to fall back to dev accounts.
    //   2. KEYSTONE_ACCOUNTS unset but ./accounts.json exists → the
    //      file-backed backend.
    //   3. KEYSTONE_DEV_SEED=1 → the stub, dev only.
    //   4. Neither → refuse to start. A server that can authenticate
    //      no one authorizes no one; running it anyway would only hide
    //      the misconfiguration.
    let accounts_env = std::env::var_os("KEYSTONE_ACCOUNTS").map(std::path::PathBuf::from);
    let accounts_path = accounts_env
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("accounts.json"));
    let dev_seed = std::env::var("KEYSTONE_DEV_SEED").as_deref() == Ok("1");
    let entitlements: Arc<dyn keystone_core::EntitlementSource> = if accounts_env.is_some()
        && !accounts_path.exists()
    {
        tracing::error!(
            path = %accounts_path.display(),
            "KEYSTONE_ACCOUNTS points at a file that does not exist — refusing to start"
        );
        exit(1);
    } else if accounts_path.exists() {
        tracing::info!(path = %accounts_path.display(), "entitlement backend: local accounts file");
        Arc::new(keystone_server::accounts::LocalAccounts::open(
            accounts_path,
        ))
    } else if let Some(stub) = dev_seed_source(dev_seed) {
        tracing::warn!("KEYSTONE_DEV_SEED=1 — stub entitlement backend with dev accounts active");
        stub
    } else {
        tracing::error!(
            "no accounts file (KEYSTONE_ACCOUNTS / ./accounts.json) and \
                 KEYSTONE_DEV_SEED is not set — refusing to start"
        );
        exit(1);
    };

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
    let payload_dir = std::env::var_os("KEYSTONE_PAYLOAD_DIR").map(std::path::PathBuf::from);
    let payload_secret = load_payload_secret();
    if payload_dir.is_none() || payload_secret.is_none() {
        tracing::warn!(
            "no KEYSTONE_PAYLOAD_DIR/KEYSTONE_PAYLOAD_SECRET — /payload routes are disabled"
        );
    }
    // The epoch is a key-derivation input: `xtask seal` must have used
    // the same one, or every artifact answers 422.
    let payload_epoch: u32 = std::env::var("KEYSTONE_PAYLOAD_EPOCH")
        .ok()
        .map(|v| {
            v.trim()
                .parse()
                .expect("KEYSTONE_PAYLOAD_EPOCH must be a u32")
        })
        .unwrap_or(0);

    let revoked_key_ids = load_revoked_key_ids();
    if !revoked_key_ids.is_empty() {
        tracing::warn!(?revoked_key_ids, "issuer keys revoked at startup");
    }

    // Pseudonymous download records for leak investigation. The log
    // lives next to the payloads unless KEYSTONE_DOWNLOAD_LOG points
    // elsewhere; no path at all means logging is off, not improvised.
    let download_log_path = std::env::var_os("KEYSTONE_DOWNLOAD_LOG")
        .map(std::path::PathBuf::from)
        .or_else(|| payload_dir.as_ref().map(|dir| dir.join("downloads.jsonl")));
    let watermark_secret = load_watermark_secret().or(payload_secret);
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
            tracing::warn!("no KEYSTONE_DOWNLOAD_LOG or payload dir — download logging disabled");
            None
        }
    };

    let state = AppState {
        issuer: Arc::new(issuer),
        store: SessionStore::new(),
        entitlements,
        admin_token_hash,
        lease_ttl: Duration::seconds(300),
        grace_period: Duration::seconds(60),
        payload_dir,
        payload_secret,
        payload_epoch,
        downloads,
        watermark_secret,
        rate_limits: RateLimits::default(),
        rate_limiter: Arc::new(RateLimiter::new()),
        artifact_hashes: Arc::new(ArtifactHashes::new()),
        revoked_key_ids: Arc::new(RwLock::new(revoked_key_ids)),
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
    let mode = match transport_mode(
        std::env::var_os("KEYSTONE_TLS_CERT").map(std::path::PathBuf::from),
        std::env::var_os("KEYSTONE_TLS_KEY").map(std::path::PathBuf::from),
        std::env::var_os("KEYSTONE_CA_CERT").map(std::path::PathBuf::from),
        is_insecure_allowed,
    ) {
        Ok(mode) => mode,
        Err(msg) => {
            eprintln!("{msg}");
            exit(1);
        }
    };
    match mode {
        TransportMode::MutualTls { cert, key, ca } => {
            let ca_pem = std::fs::read(ca).expect("reading KEYSTONE_CA_CERT");
            let cert_pem = std::fs::read(cert).expect("reading KEYSTONE_TLS_CERT");
            let key_pem = std::fs::read(key).expect("reading KEYSTONE_TLS_KEY");
            let config =
                keystone_server::tls::load_rustls_config(&cert_pem, &key_pem, Some(&ca_pem))
                    .expect("loading KEYSTONE_TLS_CERT/KEYSTONE_TLS_KEY");
            tracing::info!(%addr, "keystone-server listening (TLS, client certs required)");
            serve_tls(addr, config, state).await;
        }
        TransportMode::TlsOnly { cert, key } => {
            let cert_pem = std::fs::read(cert).expect("reading KEYSTONE_TLS_CERT");
            let key_pem = std::fs::read(key).expect("reading KEYSTONE_TLS_KEY");
            let config = keystone_server::tls::load_rustls_config(&cert_pem, &key_pem, None)
                .expect("loading KEYSTONE_TLS_CERT/KEYSTONE_TLS_KEY");
            tracing::warn!(
                %addr,
                "{ALLOW_INSECURE_VAR}=1: listening (TLS) WITHOUT client certs — cert_sha256 bindings cannot be enforced"
            );
            serve_tls(addr, config, state).await;
        }
        TransportMode::Plain => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("bind keystone-server");
            tracing::warn!(
                %addr,
                "{ALLOW_INSECURE_VAR}=1: listening WITHOUT TLS — real clients require https and will refuse"
            );
            axum::serve(
                listener,
                build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("keystone-server failed");
        }
    }
}

/// PeerCertAcceptor, not bind_rustls: handlers need the peer's
/// certificate chain for the cert_sha256 session binding, and
/// axum-server's stock acceptor discards it.
async fn serve_tls(
    addr: SocketAddr,
    config: axum_server::tls_rustls::RustlsConfig,
    state: AppState,
) {
    axum_server::Server::bind(addr)
        .acceptor(keystone_server::tls::PeerCertAcceptor::new(config))
        .serve(build_router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("keystone-server failed");
}
