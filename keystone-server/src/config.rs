//! Server configuration: the `KEYSTONE_*` environment surface and the
//! typed settings it produces.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use chrono::Duration;
use keystone_core::wire::{MAX_ADMIN_TOKEN_BYTES, MIN_ADMIN_TOKEN_LEN};
use keystone_core::{EntitlementSource, Issuer, derive_watermark_secret};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::accounts::LocalAccounts;
use crate::entitlement::dev_seed_source;
use crate::error::ServerError;
use crate::revocations::FileRevocationStore;
use crate::serve::Listeners;
use crate::state::{AppState, AppStateBuilder};
use crate::tls::{TransportMode, load_rustls_config, transport_mode};

/// Request ceilings per sliding `window` (one minute by default). Session
/// buckets are charged only for requests that proved possession of the
/// session; exchange failure buckets count failed logins only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// `/exchange` per client IP (IPv6 per /64).
    pub exchange_per_ip: u32,
    /// Failed `/exchange` logins per account under mTLS, per (account,
    /// client /64) without client certificates, and per presenting
    /// certificate (or /64) for certificates that may not act for the account.
    pub exchange_failures_per_account: u32,
    /// Failed `/exchange` logins per account across all addresses, without
    /// client certificates.
    pub exchange_failures_per_account_total: u32,
    /// Session routes (`/handoff`, `/attest`, `/heartbeat`, payload) per client IP.
    pub session_per_ip: u32,
    /// `/handoff` per session.
    pub handoff_per_session: u32,
    /// `/attest` per parent session.
    pub attest_per_session: u32,
    /// `/heartbeat` per session.
    pub heartbeat_per_session: u32,
    /// `POST /payload` per session.
    pub payload_fetch_per_session: u32,
    /// `GET /payload/{product}/{version}` per session.
    pub payload_download_per_session: u32,
    /// Failed admin token checks per client IP on the admin listener.
    pub admin_failures_per_ip: u32,
    /// The window every limit slides over.
    pub window: std::time::Duration,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            exchange_per_ip: 10,
            exchange_failures_per_account: 5,
            exchange_failures_per_account_total: 50,
            session_per_ip: 600,
            handoff_per_session: 10,
            attest_per_session: 10,
            heartbeat_per_session: 30,
            payload_fetch_per_session: 10,
            payload_download_per_session: 10,
            admin_failures_per_ip: 10,
            window: std::time::Duration::from_secs(60),
        }
    }
}

/// Why a string cannot be an [`AdminToken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AdminTokenError {
    /// Fewer than `wire::MIN_ADMIN_TOKEN_LEN` characters.
    #[error("admin token must be at least {MIN_ADMIN_TOKEN_LEN} characters")]
    TooShort,
    /// More than `wire::MAX_ADMIN_TOKEN_BYTES` bytes.
    #[error("admin token must be at most {MAX_ADMIN_TOKEN_BYTES} bytes")]
    TooLong,
}

/// The operator credential for the admin router. Kept only as its sha256;
/// `Debug` never shows it.
#[derive(Clone)]
pub struct AdminToken {
    hash: [u8; 32],
}

impl AdminToken {
    /// Accept a token of at least `wire::MIN_ADMIN_TOKEN_LEN` characters and
    /// at most `wire::MAX_ADMIN_TOKEN_BYTES` bytes.
    pub fn new(token: &str) -> Result<Self, AdminTokenError> {
        if token.chars().count() < MIN_ADMIN_TOKEN_LEN {
            return Err(AdminTokenError::TooShort);
        }
        if token.len() > MAX_ADMIN_TOKEN_BYTES {
            return Err(AdminTokenError::TooLong);
        }
        Ok(Self {
            hash: Sha256::digest(token.as_bytes()).into(),
        })
    }

    /// Constant-time check of a presented token.
    pub fn matches(&self, presented: &str) -> bool {
        let presented: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        presented.ct_eq(&self.hash).into()
    }
}

impl fmt::Debug for AdminToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdminToken([redacted])")
    }
}

/// Where sealed releases live and the secrets that key them. Artifacts are
/// `{dir}/{product}/{version}.bin` with `.sha256` and `.build` sidecars.
#[derive(Clone)]
pub struct PayloadConfig {
    /// Payload directory.
    pub dir: PathBuf,
    /// Artifact secret the sealed blobs are keyed under.
    pub secret: Zeroizing<[u8; 32]>,
    /// Rotation counter mixed into every artifact key.
    pub epoch: u32,
    /// Keys manifest download ids and download log pseudonyms.
    pub watermark_secret: Zeroizing<[u8; 32]>,
}

impl PayloadConfig {
    /// A payload config whose watermark secret is derived from `secret`.
    pub fn new(dir: impl Into<PathBuf>, secret: [u8; 32], epoch: u32) -> Self {
        let watermark_secret = derive_watermark_secret(&secret);
        Self {
            dir: dir.into(),
            secret: Zeroizing::new(secret),
            epoch,
            watermark_secret,
        }
    }

    /// Replace the derived watermark secret.
    pub fn with_watermark_secret(mut self, watermark_secret: [u8; 32]) -> Self {
        self.watermark_secret = Zeroizing::new(watermark_secret);
        self
    }
}

impl fmt::Debug for PayloadConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayloadConfig")
            .field("dir", &self.dir)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Everything the server takes from its environment. `Debug` shows no
/// secrets.
#[derive(Debug)]
pub struct ServerConfig {
    /// Public listener (`KEYSTONE_BIND`).
    pub bind: SocketAddr,
    /// Admin listener (`KEYSTONE_ADMIN_BIND`); served only with an admin token.
    pub admin_bind: SocketAddr,
    /// TLS mode for both listeners.
    pub transport: TransportMode,
    /// The active signing key (`KEYSTONE_KEYFILE`).
    pub issuer: Issuer,
    /// Admin credential; `None` turns the admin listener off.
    pub admin_token: Option<AdminToken>,
    /// sha256 of the leaf certificates allowed on the admin listener
    /// (`KEYSTONE_ADMIN_CERT_SHA256`); required with an admin token under mTLS.
    pub admin_certificates: BTreeSet<[u8; 32]>,
    /// Lease lifetime per grant or renewal.
    pub lease_ttl: Duration,
    /// Grace the client may run on after a transient failure.
    pub grace_period: Duration,
    /// Per-minute ceilings.
    pub rate_limits: RateLimits,
    /// Payload routes; `None` answers them with 503.
    pub payloads: Option<PayloadConfig>,
    /// Download log path; requires `payloads`.
    pub download_log: Option<PathBuf>,
    /// Issuer key ids revoked at startup (`KEYSTONE_REVOKED_KEY_IDS`).
    pub revoked_key_ids: BTreeSet<u8>,
    /// Revocation file backing the default `FileRevocationStore`
    /// (`KEYSTONE_REVOCATIONS_FILE`).
    pub revocations_file: PathBuf,
}

impl ServerConfig {
    /// Read the configuration from `KEYSTONE_*` variables. Every missing
    /// required or unparsable value is a [`ServerError::Config`] naming the
    /// variable.
    pub fn from_env() -> Result<Self, ServerError> {
        Self::from_lookup(&|var| std::env::var_os(var))
    }

    fn from_lookup(get: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, ServerError> {
        let env = Env(get);
        env.reject_removed()?;
        let allow_insecure = env.flag("KEYSTONE_ALLOW_INSECURE")?;

        let bind = env
            .parse("KEYSTONE_BIND")?
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 8443)));
        let admin_bind = env
            .parse("KEYSTONE_ADMIN_BIND")?
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8444)));

        let issuer = match env.path("KEYSTONE_KEYFILE") {
            Some(path) => {
                let bytes = Zeroizing::new(std::fs::read(&path).map_err(|e| {
                    ServerError::config("KEYSTONE_KEYFILE", format!("{}: {e}", path.display()))
                })?);
                Issuer::from_keyfile(&bytes)
                    .map_err(|e| ServerError::config("KEYSTONE_KEYFILE", e.to_string()))?
            }
            None if allow_insecure => {
                tracing::warn!("no KEYSTONE_KEYFILE: ephemeral issuer key 1");
                Issuer::generate(1)
            }
            None => {
                return Err(ServerError::config(
                    "KEYSTONE_KEYFILE",
                    "required unless KEYSTONE_ALLOW_INSECURE=1",
                ));
            }
        };

        let revoked_key_ids = match env.text("KEYSTONE_REVOKED_KEY_IDS")? {
            Some(list) => list
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.parse::<u8>().map_err(|_| {
                        ServerError::config(
                            "KEYSTONE_REVOKED_KEY_IDS",
                            format!("{s:?} is not a key id"),
                        )
                    })
                })
                .collect::<Result<_, _>>()?,
            None => BTreeSet::new(),
        };
        let revocations_file = env
            .path("KEYSTONE_REVOCATIONS_FILE")
            .unwrap_or_else(|| PathBuf::from("revoked-keys.json"));

        let admin_token = env
            .text("KEYSTONE_ADMIN_TOKEN")?
            .map(|t| {
                AdminToken::new(&Zeroizing::new(t))
                    .map_err(|e| ServerError::config("KEYSTONE_ADMIN_TOKEN", e.to_string()))
            })
            .transpose()?;

        let transport = transport_mode(
            env.path("KEYSTONE_TLS_CERT"),
            env.path("KEYSTONE_TLS_KEY"),
            env.path("KEYSTONE_CA_CERT"),
            allow_insecure,
        )?;
        let admin_certificates = env.admin_certificates()?;
        let mutual_tls = matches!(transport, TransportMode::MutualTls { .. });
        match (
            admin_token.is_some(),
            mutual_tls,
            admin_certificates.is_empty(),
        ) {
            (true, true, true) => {
                return Err(ServerError::config(
                    "KEYSTONE_ADMIN_CERT_SHA256",
                    "required when KEYSTONE_ADMIN_TOKEN is set under mTLS",
                ));
            }
            (false, _, false) => {
                return Err(ServerError::config(
                    "KEYSTONE_ADMIN_CERT_SHA256",
                    "requires KEYSTONE_ADMIN_TOKEN",
                ));
            }
            (true, false, false) => {
                return Err(ServerError::config(
                    "KEYSTONE_ADMIN_CERT_SHA256",
                    "requires KEYSTONE_CA_CERT",
                ));
            }
            _ => {}
        }

        let payloads = env.payloads()?;
        let download_log = env.path("KEYSTONE_DOWNLOAD_LOG");
        if download_log.is_some() && payloads.is_none() {
            return Err(ServerError::config(
                "KEYSTONE_DOWNLOAD_LOG",
                "requires KEYSTONE_PAYLOAD_DIR",
            ));
        }

        let lease_secs: u32 = env.parse("KEYSTONE_LEASE_TTL_SECS")?.unwrap_or(300);
        if lease_secs == 0 {
            return Err(ServerError::config(
                "KEYSTONE_LEASE_TTL_SECS",
                "must be positive",
            ));
        }
        let grace_secs: u32 = env.parse("KEYSTONE_GRACE_SECS")?.unwrap_or(60);

        Ok(Self {
            bind,
            admin_bind,
            transport,
            issuer,
            admin_token,
            admin_certificates,
            lease_ttl: Duration::seconds(lease_secs.into()),
            grace_period: Duration::seconds(grace_secs.into()),
            rate_limits: env.rate_limits()?,
            payloads,
            download_log,
            revoked_key_ids,
            revocations_file,
        })
    }

    /// Load the TLS material, bind the listeners, and return a builder
    /// populated from this configuration: a `FileRevocationStore` over
    /// `revocations_file`, the admin allow-list, and required client
    /// certificates under mTLS. Override any seam, then call
    /// [`AppStateBuilder::build`]. The admin listener is bound only when an
    /// admin token is set.
    pub fn into_parts(
        self,
        entitlements: Arc<dyn EntitlementSource>,
    ) -> Result<(AppStateBuilder, Listeners), ServerError> {
        let tls = match &self.transport {
            TransportMode::MutualTls { cert, key, ca } => Some(load_tls(cert, key, Some(ca))?),
            TransportMode::TlsOnly { cert, key } => {
                tracing::warn!("TLS without client certificates: sessions are not cert-bound");
                Some(load_tls(cert, key, None)?)
            }
            TransportMode::Plain => {
                tracing::warn!("listening without TLS");
                None
            }
        };
        let has_admin = self.admin_token.is_some();
        let mut builder = AppState::builder(self.issuer, entitlements)
            .revocations(Arc::new(FileRevocationStore::new(self.revocations_file)))
            .lease_ttl(self.lease_ttl)
            .grace_period(self.grace_period)
            .rate_limits(self.rate_limits)
            .revoked_key_ids(self.revoked_key_ids)
            .admin_certificates(self.admin_certificates)
            .require_client_certificates(matches!(self.transport, TransportMode::MutualTls { .. }));
        if let Some(token) = self.admin_token {
            builder = builder.admin_token(token);
        }
        if let Some(payloads) = self.payloads {
            builder = builder.payloads(payloads);
        }
        if let Some(path) = self.download_log {
            builder = builder.download_log(path);
        }

        let public = bind(self.bind)?;
        let admin = if has_admin {
            Some(bind(self.admin_bind)?)
        } else {
            tracing::warn!("no KEYSTONE_ADMIN_TOKEN: admin listener disabled");
            None
        };
        let listeners = Listeners::from_std(public, admin, tls).map_err(ServerError::Serve)?;
        Ok((builder, listeners))
    }
}

/// The binary's entitlement backend: `KEYSTONE_ACCOUNTS` (must exist), else
/// `./accounts.json` when present, else the dev stub when
/// `KEYSTONE_DEV_SEED=1` and `KEYSTONE_ALLOW_INSECURE=1`.
pub fn entitlements_from_env() -> Result<Arc<dyn EntitlementSource>, ServerError> {
    entitlements_from_lookup(&|var| std::env::var_os(var))
}

fn entitlements_from_lookup(
    get: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Arc<dyn EntitlementSource>, ServerError> {
    let env = Env(get);
    let dev_seed = env.flag("KEYSTONE_DEV_SEED")?;
    let allow_insecure = env.flag("KEYSTONE_ALLOW_INSECURE")?;
    if let Some(path) = env.path("KEYSTONE_ACCOUNTS") {
        if !path.is_file() {
            return Err(ServerError::config(
                "KEYSTONE_ACCOUNTS",
                format!("{} does not exist", path.display()),
            ));
        }
        return Ok(Arc::new(LocalAccounts::open(path)));
    }
    let default_path = PathBuf::from("accounts.json");
    if default_path.is_file() {
        return Ok(Arc::new(LocalAccounts::open(default_path)));
    }
    match (dev_seed, allow_insecure) {
        (true, true) => {
            tracing::warn!("KEYSTONE_DEV_SEED=1: dev accounts active");
            Ok(dev_seed_source())
        }
        (true, false) => Err(ServerError::config(
            "KEYSTONE_DEV_SEED",
            "requires KEYSTONE_ALLOW_INSECURE=1",
        )),
        (false, _) => Err(ServerError::config(
            "KEYSTONE_ACCOUNTS",
            "no accounts file and KEYSTONE_DEV_SEED is not set",
        )),
    }
}

fn load_tls(
    cert: &PathBuf,
    key: &PathBuf,
    ca: Option<&PathBuf>,
) -> Result<axum_server::tls_rustls::RustlsConfig, ServerError> {
    let read = |var: &'static str, path: &PathBuf| {
        std::fs::read(path)
            .map_err(|e| ServerError::config(var, format!("{}: {e}", path.display())))
    };
    let cert_pem = read("KEYSTONE_TLS_CERT", cert)?;
    let key_pem = Zeroizing::new(read("KEYSTONE_TLS_KEY", key)?);
    let ca_pem = ca.map(|ca| read("KEYSTONE_CA_CERT", ca)).transpose()?;
    load_rustls_config(&cert_pem, &key_pem, ca_pem.as_deref()).map_err(ServerError::Tls)
}

fn bind(addr: SocketAddr) -> Result<std::net::TcpListener, ServerError> {
    std::net::TcpListener::bind(addr).map_err(|source| ServerError::Bind { addr, source })
}

struct Env<'a>(&'a dyn Fn(&str) -> Option<OsString>);

impl Env<'_> {
    fn path(&self, var: &str) -> Option<PathBuf> {
        (self.0)(var).map(PathBuf::from)
    }

    fn text(&self, var: &'static str) -> Result<Option<String>, ServerError> {
        (self.0)(var)
            .map(|v| {
                v.into_string()
                    .map_err(|_| ServerError::config(var, "not valid UTF-8"))
            })
            .transpose()
    }

    fn parse<T: FromStr>(&self, var: &'static str) -> Result<Option<T>, ServerError>
    where
        T::Err: fmt::Display,
    {
        self.text(var)?
            .map(|v| {
                v.trim()
                    .parse()
                    .map_err(|e| ServerError::config(var, format!("{v:?}: {e}")))
            })
            .transpose()
    }

    fn flag(&self, var: &'static str) -> Result<bool, ServerError> {
        match self.text(var)?.as_deref() {
            None | Some("0") => Ok(false),
            Some("1") => Ok(true),
            Some(other) => Err(ServerError::config(
                var,
                format!("{other:?}: must be 0 or 1"),
            )),
        }
    }

    fn reject_removed(&self) -> Result<(), ServerError> {
        const REMOVED: [(&str, &str); 4] = [
            ("KEYSTONE_PORT", "KEYSTONE_BIND"),
            ("KEYSTONE_KEY_ID", "KEYSTONE_KEYFILE"),
            ("KEYSTONE_SEED", "KEYSTONE_KEYFILE"),
            ("KEYSTONE_PAYLOAD_SECRET", "KEYSTONE_PAYLOAD_SECRET_FILE"),
        ];
        for (var, replacement) in REMOVED {
            if (self.0)(var).is_some() {
                return Err(ServerError::config(
                    var,
                    format!("no longer supported; use {replacement}"),
                ));
            }
        }
        Ok(())
    }

    fn payloads(&self) -> Result<Option<PayloadConfig>, ServerError> {
        let dir = self.path("KEYSTONE_PAYLOAD_DIR");
        let secret_file = self.path("KEYSTONE_PAYLOAD_SECRET_FILE");
        let (dir, secret_file) = match (dir, secret_file) {
            (Some(dir), Some(file)) => (dir, file),
            (None, None) => {
                for var in ["KEYSTONE_PAYLOAD_EPOCH", "KEYSTONE_WATERMARK_SECRET"] {
                    if (self.0)(var).is_some() {
                        return Err(ServerError::config(var, "requires KEYSTONE_PAYLOAD_DIR"));
                    }
                }
                return Ok(None);
            }
            (Some(_), None) => {
                return Err(ServerError::config(
                    "KEYSTONE_PAYLOAD_SECRET_FILE",
                    "required when KEYSTONE_PAYLOAD_DIR is set",
                ));
            }
            (None, Some(_)) => {
                return Err(ServerError::config(
                    "KEYSTONE_PAYLOAD_DIR",
                    "required when KEYSTONE_PAYLOAD_SECRET_FILE is set",
                ));
            }
        };
        let bytes = Zeroizing::new(std::fs::read(&secret_file).map_err(|e| {
            ServerError::config(
                "KEYSTONE_PAYLOAD_SECRET_FILE",
                format!("{}: {e}", secret_file.display()),
            )
        })?);
        let secret: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            ServerError::config("KEYSTONE_PAYLOAD_SECRET_FILE", "must hold exactly 32 bytes")
        })?;
        let epoch = self.parse("KEYSTONE_PAYLOAD_EPOCH")?.unwrap_or(0);
        let mut config = PayloadConfig::new(dir, secret, epoch);
        if let Some(hex_secret) = self.text("KEYSTONE_WATERMARK_SECRET")? {
            let bytes = Zeroizing::new(hex::decode(hex_secret.trim()).map_err(|_| {
                ServerError::config("KEYSTONE_WATERMARK_SECRET", "must be 64 hex characters")
            })?);
            let watermark: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                ServerError::config("KEYSTONE_WATERMARK_SECRET", "must be 64 hex characters")
            })?;
            config = config.with_watermark_secret(watermark);
        }
        Ok(Some(config))
    }

    /// `KEYSTONE_ADMIN_CERT_SHA256`: comma-separated 64-character hex hashes.
    fn admin_certificates(&self) -> Result<BTreeSet<[u8; 32]>, ServerError> {
        const VAR: &str = "KEYSTONE_ADMIN_CERT_SHA256";
        let Some(list) = self.text(VAR)? else {
            return Ok(BTreeSet::new());
        };
        let hashes: BTreeSet<[u8; 32]> = list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                hex::decode(s)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                    .ok_or_else(|| {
                        ServerError::config(VAR, format!("{s:?} is not a 64-character hex hash"))
                    })
            })
            .collect::<Result<_, _>>()?;
        if hashes.is_empty() {
            return Err(ServerError::config(VAR, "set but lists no hashes"));
        }
        Ok(hashes)
    }

    fn rate_limits(&self) -> Result<RateLimits, ServerError> {
        let mut limits = RateLimits::default();
        let fields: [(&'static str, &mut u32); 10] = [
            ("KEYSTONE_RATE_EXCHANGE_PER_IP", &mut limits.exchange_per_ip),
            (
                "KEYSTONE_RATE_EXCHANGE_FAILURES_PER_ACCOUNT",
                &mut limits.exchange_failures_per_account,
            ),
            (
                "KEYSTONE_RATE_EXCHANGE_FAILURES_PER_ACCOUNT_TOTAL",
                &mut limits.exchange_failures_per_account_total,
            ),
            ("KEYSTONE_RATE_SESSION_PER_IP", &mut limits.session_per_ip),
            (
                "KEYSTONE_RATE_HANDOFF_PER_SESSION",
                &mut limits.handoff_per_session,
            ),
            (
                "KEYSTONE_RATE_ATTEST_PER_SESSION",
                &mut limits.attest_per_session,
            ),
            (
                "KEYSTONE_RATE_HEARTBEAT_PER_SESSION",
                &mut limits.heartbeat_per_session,
            ),
            (
                "KEYSTONE_RATE_PAYLOAD_FETCH_PER_SESSION",
                &mut limits.payload_fetch_per_session,
            ),
            (
                "KEYSTONE_RATE_PAYLOAD_DOWNLOAD_PER_SESSION",
                &mut limits.payload_download_per_session,
            ),
            (
                "KEYSTONE_RATE_ADMIN_FAILURES_PER_IP",
                &mut limits.admin_failures_per_ip,
            ),
        ];
        for (var, slot) in fields {
            if let Some(value) = self.parse::<u32>(var)? {
                if value == 0 {
                    return Err(ServerError::config(var, "must be positive"));
                }
                *slot = value;
            }
        }
        Ok(limits)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn keyfile() -> PathBuf {
        let path = std::env::temp_dir().join(format!("keystone-cfg-{}.key", uuid::Uuid::new_v4()));
        std::fs::write(&path, &Issuer::generate(4).keyfile_bytes()[..]).unwrap();
        path
    }

    fn config(vars: &[(&str, &str)]) -> Result<ServerConfig, ServerError> {
        let map: HashMap<String, OsString> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        ServerConfig::from_lookup(&move |var| map.get(var).cloned())
    }

    fn config_var(result: Result<ServerConfig, ServerError>) -> &'static str {
        match result {
            Err(ServerError::Config { var, .. }) => var,
            Err(other) => panic!("expected a Config error, got {other}"),
            Ok(_) => panic!("expected a Config error, got a config"),
        }
    }

    #[test]
    fn insecure_minimum_uses_documented_defaults() {
        let cfg = config(&[("KEYSTONE_ALLOW_INSECURE", "1")]).unwrap();
        assert_eq!(cfg.bind, "0.0.0.0:8443".parse().unwrap());
        assert_eq!(cfg.admin_bind, "127.0.0.1:8444".parse().unwrap());
        assert_eq!(cfg.transport, TransportMode::Plain);
        assert!(cfg.admin_token.is_none());
        assert_eq!(cfg.revocations_file, PathBuf::from("revoked-keys.json"));
    }

    #[test]
    fn keyfile_is_required_without_insecure_mode() {
        assert_eq!(config_var(config(&[])), "KEYSTONE_KEYFILE");
    }

    #[test]
    fn keyfile_supplies_the_key_id() {
        let path = keyfile();
        let cfg = config(&[
            ("KEYSTONE_ALLOW_INSECURE", "1"),
            ("KEYSTONE_KEYFILE", path.to_str().unwrap()),
        ])
        .unwrap();
        assert_eq!(cfg.issuer.key_id(), 4);
    }

    #[test]
    fn bare_seed_keyfile_is_rejected() {
        let path = std::env::temp_dir().join(format!("keystone-cfg-{}.key", uuid::Uuid::new_v4()));
        std::fs::write(&path, [7u8; 32]).unwrap();
        let result = config(&[
            ("KEYSTONE_ALLOW_INSECURE", "1"),
            ("KEYSTONE_KEYFILE", path.to_str().unwrap()),
        ]);
        assert_eq!(config_var(result), "KEYSTONE_KEYFILE");
    }

    #[test]
    fn short_admin_token_is_a_config_error() {
        let short = "x".repeat(MIN_ADMIN_TOKEN_LEN - 1);
        let result = config(&[
            ("KEYSTONE_ALLOW_INSECURE", "1"),
            ("KEYSTONE_ADMIN_TOKEN", &short),
        ]);
        assert_eq!(config_var(result), "KEYSTONE_ADMIN_TOKEN");
        let empty = config(&[
            ("KEYSTONE_ALLOW_INSECURE", "1"),
            ("KEYSTONE_ADMIN_TOKEN", ""),
        ]);
        assert_eq!(config_var(empty), "KEYSTONE_ADMIN_TOKEN");
    }

    #[test]
    fn admin_token_bounds_are_characters_and_bytes() {
        assert_eq!(
            AdminToken::new(&"x".repeat(MIN_ADMIN_TOKEN_LEN - 1)).err(),
            Some(AdminTokenError::TooShort)
        );
        assert!(AdminToken::new(&"x".repeat(MIN_ADMIN_TOKEN_LEN)).is_ok());
        assert_eq!(
            AdminToken::new(&"x".repeat(MAX_ADMIN_TOKEN_BYTES + 1)).err(),
            Some(AdminTokenError::TooLong)
        );
    }

    #[test]
    fn admin_token_matches_only_itself() {
        let token = AdminToken::new(&"a".repeat(40)).unwrap();
        assert!(token.matches(&"a".repeat(40)));
        assert!(!token.matches(&"a".repeat(41)));
        assert!(!token.matches(""));
        assert!(!format!("{token:?}").contains("aaaa"));
    }

    const MTLS: [(&str, &str); 3] = [
        ("KEYSTONE_TLS_CERT", "cert.pem"),
        ("KEYSTONE_TLS_KEY", "key.pem"),
        ("KEYSTONE_CA_CERT", "ca.pem"),
    ];

    #[test]
    fn admin_listener_under_mtls_needs_an_allow_list() {
        let keyfile = keyfile();
        let token = "t".repeat(MIN_ADMIN_TOKEN_LEN);
        let mut vars = vec![
            ("KEYSTONE_KEYFILE", keyfile.to_str().unwrap()),
            ("KEYSTONE_ADMIN_TOKEN", token.as_str()),
        ];
        vars.extend(MTLS);
        assert_eq!(config_var(config(&vars)), "KEYSTONE_ADMIN_CERT_SHA256");

        let (a, b) = (hex::encode([1u8; 32]), hex::encode([2u8; 32]));
        let list = format!("{a}, {b}");
        vars.push(("KEYSTONE_ADMIN_CERT_SHA256", &list));
        let cfg = config(&vars).unwrap();
        assert_eq!(
            cfg.admin_certificates,
            BTreeSet::from([[1u8; 32], [2u8; 32]])
        );
    }

    #[test]
    fn admin_allow_list_is_validated() {
        let keyfile = keyfile();
        let token = "t".repeat(MIN_ADMIN_TOKEN_LEN);
        let good = hex::encode([1u8; 32]);
        for (with_token, with_mtls, list) in [
            (true, true, "abcd"),
            (true, true, " , "),
            (false, true, good.as_str()),
            (true, false, good.as_str()),
        ] {
            let mut vars = vec![
                ("KEYSTONE_KEYFILE", keyfile.to_str().unwrap()),
                ("KEYSTONE_ALLOW_INSECURE", "1"),
                ("KEYSTONE_ADMIN_CERT_SHA256", list),
            ];
            if with_token {
                vars.push(("KEYSTONE_ADMIN_TOKEN", &token));
            }
            if with_mtls {
                vars.extend(MTLS);
            }
            assert_eq!(
                config_var(config(&vars)),
                "KEYSTONE_ADMIN_CERT_SHA256",
                "{with_token} {with_mtls} {list:?}"
            );
        }
    }

    #[test]
    fn removed_variables_are_refused() {
        for var in [
            "KEYSTONE_PORT",
            "KEYSTONE_KEY_ID",
            "KEYSTONE_SEED",
            "KEYSTONE_PAYLOAD_SECRET",
        ] {
            let result = config(&[("KEYSTONE_ALLOW_INSECURE", "1"), (var, "1")]);
            assert_eq!(config_var(result), var);
        }
    }

    #[test]
    fn every_unparsable_value_names_its_variable() {
        let cases = [
            ("KEYSTONE_ALLOW_INSECURE", "yes"),
            ("KEYSTONE_BIND", "8443"),
            ("KEYSTONE_ADMIN_BIND", "localhost"),
            ("KEYSTONE_REVOKED_KEY_IDS", "1,300"),
            ("KEYSTONE_LEASE_TTL_SECS", "0"),
            ("KEYSTONE_LEASE_TTL_SECS", "-5"),
            ("KEYSTONE_GRACE_SECS", "1m"),
            ("KEYSTONE_RATE_EXCHANGE_PER_IP", "many"),
            ("KEYSTONE_RATE_ADMIN_FAILURES_PER_IP", "0"),
            ("KEYSTONE_RATE_EXCHANGE_FAILURES_PER_ACCOUNT_TOTAL", "x"),
            ("KEYSTONE_PAYLOAD_DIR", "payloads"),
            ("KEYSTONE_PAYLOAD_EPOCH", "1"),
            ("KEYSTONE_DOWNLOAD_LOG", "downloads.jsonl"),
        ];
        for (var, value) in cases {
            let mut vars = vec![(var, value)];
            if var != "KEYSTONE_ALLOW_INSECURE" {
                vars.push(("KEYSTONE_ALLOW_INSECURE", "1"));
            }
            let got = config_var(config(&vars));
            let expected = match var {
                "KEYSTONE_PAYLOAD_DIR" => "KEYSTONE_PAYLOAD_SECRET_FILE",
                other => other,
            };
            assert_eq!(got, expected, "{var}={value}");
        }
    }

    #[test]
    fn payload_secret_file_must_hold_32_bytes() {
        let dir = std::env::temp_dir().join(format!("keystone-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("secret");
        std::fs::write(&secret, [1u8; 31]).unwrap();
        let result = config(&[
            ("KEYSTONE_ALLOW_INSECURE", "1"),
            ("KEYSTONE_PAYLOAD_DIR", dir.to_str().unwrap()),
            ("KEYSTONE_PAYLOAD_SECRET_FILE", secret.to_str().unwrap()),
        ]);
        assert_eq!(config_var(result), "KEYSTONE_PAYLOAD_SECRET_FILE");

        std::fs::write(&secret, [1u8; 32]).unwrap();
        let cfg = config(&[
            ("KEYSTONE_ALLOW_INSECURE", "1"),
            ("KEYSTONE_PAYLOAD_DIR", dir.to_str().unwrap()),
            ("KEYSTONE_PAYLOAD_SECRET_FILE", secret.to_str().unwrap()),
            ("KEYSTONE_WATERMARK_SECRET", "zz"),
        ]);
        assert_eq!(config_var(cfg), "KEYSTONE_WATERMARK_SECRET");
    }

    #[test]
    fn tls_needs_ca_unless_insecure() {
        let result = config(&[
            ("KEYSTONE_KEYFILE", keyfile().to_str().unwrap()),
            ("KEYSTONE_TLS_CERT", "cert.pem"),
            ("KEYSTONE_TLS_KEY", "key.pem"),
        ]);
        assert_eq!(config_var(result), "KEYSTONE_CA_CERT");
        let half = config(&[
            ("KEYSTONE_ALLOW_INSECURE", "1"),
            ("KEYSTONE_TLS_CERT", "cert.pem"),
        ]);
        assert_eq!(config_var(half), "KEYSTONE_TLS_KEY");
    }

    fn entitlement_var(vars: &[(&str, OsString)]) -> Option<&'static str> {
        let map: HashMap<&str, OsString> = vars.iter().cloned().collect();
        match entitlements_from_lookup(&|var| map.get(var).cloned()) {
            Err(ServerError::Config { var, .. }) => Some(var),
            Err(other) => panic!("unexpected error {other}"),
            Ok(_) => None,
        }
    }

    #[test]
    fn configured_accounts_file_must_exist() {
        let missing = std::env::temp_dir().join(format!("{}.json", uuid::Uuid::new_v4()));
        let vars = [
            ("KEYSTONE_ACCOUNTS", OsString::from(missing)),
            ("KEYSTONE_DEV_SEED", OsString::from("1")),
            ("KEYSTONE_ALLOW_INSECURE", OsString::from("1")),
        ];
        assert_eq!(entitlement_var(&vars), Some("KEYSTONE_ACCOUNTS"));
    }

    #[test]
    fn dev_seed_requires_insecure_mode() {
        let vars = [("KEYSTONE_DEV_SEED", OsString::from("1"))];
        assert_eq!(entitlement_var(&vars), Some("KEYSTONE_DEV_SEED"));
    }
}
