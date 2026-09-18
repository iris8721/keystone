//! keystone-server entry point: load the issuer key, build state, serve.

use std::net::SocketAddr;
use std::process::exit;
use std::sync::Arc;

use chrono::Duration;
use keystone_core::Issuer;
use keystone_server::downloads::DownloadLog;
use keystone_server::entitlement::dev_seed_source;
use keystone_server::state::{ArtifactHashes, ChallengeBook, RateLimiter, RateLimits};
use keystone_server::{build_router, AppState, SessionStore};
use sha2::{Digest, Sha256};
use tracing_subscriber::EnvFilter;

/// Load the issuer's 32-byte ed25519 seed.
///
/// KEYSTONE_KEYFILE — path to a file holding the raw 32-byte seed.
/// KEYSTONE_SEED    — the seed as a 64-char hex string.
/// Neither set      — ephemeral key + warning. Fine for development;
///                      every signature dies with the process, which is
///                      exactly what a missing key should mean.
fn load_issuer() -> Issuer {
    if let Ok(path) = std::env::var("KEYSTONE_KEYFILE") {
        let bytes =
            std::fs::read(&path).unwrap_or_else(|e| panic!("KEYSTONE_KEYFILE {path}: {e}"));
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .expect("KEYSTONE_KEYFILE must contain exactly 32 bytes");
        return Issuer::from_bytes(&seed);
    }
    if let Ok(hex_seed) = std::env::var("KEYSTONE_SEED") {
        let bytes = hex::decode(hex_seed.trim()).expect("KEYSTONE_SEED must be hex");
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .expect("KEYSTONE_SEED must decode to exactly 32 bytes");
        return Issuer::from_bytes(&seed);
    }
    tracing::warn!(
        "no KEYSTONE_KEYFILE or KEYSTONE_SEED — ephemeral issuer key; \
         all signatures die with this process"
    );
    Issuer::generate()
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
        let bytes =
            hex::decode(hex_secret.trim()).expect("KEYSTONE_PAYLOAD_SECRET must be hex");
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
    let bytes =
        hex::decode(hex_secret.trim()).expect("KEYSTONE_WATERMARK_SECRET must be hex");
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
    let entitlements: Arc<dyn keystone_core::EntitlementSource> =
        if accounts_env.is_some() && !accounts_path.exists() {
            tracing::error!(
                path = %accounts_path.display(),
                "KEYSTONE_ACCOUNTS points at a file that does not exist — refusing to start"
            );
            exit(1);
        } else if accounts_path.exists() {
            tracing::info!(path = %accounts_path.display(), "entitlement backend: local accounts file");
            Arc::new(keystone_server::accounts::LocalAccounts::open(accounts_path))
        } else if let Some(stub) = dev_seed_source(dev_seed) {
            tracing::warn!(
                "KEYSTONE_DEV_SEED=1 — stub entitlement backend with dev accounts active"
            );
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
            tracing::warn!("download log configured but no KEYSTONE_WATERMARK_SECRET/payload secret — logging disabled");
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
        challenges: Arc::new(ChallengeBook::new()),
        admin_token_hash,
        challenge_ttl: Duration::seconds(60),
        lease_ttl: Duration::seconds(300),
        grace_period: Duration::seconds(60),
        payload_dir,
        payload_secret,
        downloads,
        watermark_secret,
        rate_limits: RateLimits::default(),
        rate_limiter: Arc::new(RateLimiter::new()),
        artifact_hashes: Arc::new(ArtifactHashes::new()),
    };


    let port: u16 = std::env::var("KEYSTONE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8443);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    // TLS is mandatory in production — the client refuses plain http.
    // Both PEM paths must be set together: a half-configured pair is a
    // misconfiguration, and silently downgrading to cleartext would
    // hide it. Neither set stays allowed as a dev convenience only.
    let tls_cert = std::env::var_os("KEYSTONE_TLS_CERT");
    let tls_key = std::env::var_os("KEYSTONE_TLS_KEY");
    match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            // KEYSTONE_CA_CERT turns on mTLS: client certs are required
            // and verified against the keystone CA. Unset stays allowed
            // for dev — the warn keeps the gap loud.
            let ca_pem = std::env::var_os("KEYSTONE_CA_CERT")
                .map(|p| std::fs::read(p).expect("reading KEYSTONE_CA_CERT"));
            if ca_pem.is_none() {
                tracing::warn!(
                    "no KEYSTONE_CA_CERT — TLS client certs are NOT required (dev mode)"
                );
            }
            let cert_pem = std::fs::read(&cert).expect("reading KEYSTONE_TLS_CERT");
            let key_pem = std::fs::read(&key).expect("reading KEYSTONE_TLS_KEY");
            let config = keystone_server::tls::load_rustls_config(
                &cert_pem,
                &key_pem,
                ca_pem.as_deref(),
            )
            .expect("loading KEYSTONE_TLS_CERT/KEYSTONE_TLS_KEY");
            if ca_pem.is_some() {
                tracing::info!(%addr, "keystone-server listening (TLS, client certs required)");
            } else {
                tracing::info!(%addr, "keystone-server listening (TLS)");
            }
            // PeerCertAcceptor, not bind_rustls: handlers need the
            // peer's certificate chain for the cert_sha256 account
            // binding, and axum-server's stock acceptor discards it.
            axum_server::Server::bind(addr)
                .acceptor(keystone_server::tls::PeerCertAcceptor::new(config))
                .serve(build_router(state).into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("keystone-server failed");
        }
        (None, None) => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("bind keystone-server");
            tracing::warn!(
                %addr,
                "keystone-server listening WITHOUT TLS — real clients require https and will refuse"
            );
            axum::serve(
                listener,
                build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
                .await
                .expect("keystone-server failed");
        }
        _ => {
            eprintln!(
                "KEYSTONE_TLS_CERT and KEYSTONE_TLS_KEY must be set together — refusing to start"
            );
            exit(1);
        }
    }
}
