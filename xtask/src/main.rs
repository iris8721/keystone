//! Keystone build/deploy orchestration.
//!
//! All key/cert provisioning and deploy flows funnel through here so the
//! operator-facing steps live in one place instead of scattered scripts.
//!
//! Common flow:
//!   cargo xtask dev        (first run: provisions key + cert, starts server)
//!   cargo xtask verify     (preflight checklist)
//!   cargo xtask deploy     (release build + scp to the [target] host)

use anyhow::{Context, Result, bail};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use chrono::Utc;
use keystone_core::{AccountFile, AccountGrant, AccountRecord, Issuer};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};

#[derive(Debug, Deserialize)]
struct Config {
    target: TargetCfg,
    deploy: DeployCfg,
    #[serde(default)]
    paths: PathsCfg,
}

#[derive(Debug, Deserialize)]
struct TargetCfg {
    host: String,
    username: String,
}

#[derive(Debug, Deserialize)]
struct DeployCfg {
    remote_path: String,
}

#[derive(Debug, Deserialize)]
struct PathsCfg {
    #[serde(default = "default_keyfile")]
    keyfile: String,
    #[serde(default = "default_cert")]
    cert: String,
    #[serde(default = "default_cert_key")]
    cert_key: String,
    #[serde(default = "default_ca_cert")]
    ca_cert: String,
    #[serde(default = "default_ca_key")]
    ca_key: String,
    #[serde(default = "default_payload_secret")]
    payload_secret: String,
}

impl Default for PathsCfg {
    fn default() -> Self {
        Self {
            keyfile: default_keyfile(),
            cert: default_cert(),
            cert_key: default_cert_key(),
            ca_cert: default_ca_cert(),
            ca_key: default_ca_key(),
            payload_secret: default_payload_secret(),
        }
    }
}

fn default_keyfile() -> String {
    "keystone.key".into()
}
fn default_cert() -> String {
    "keystone-cert.pem".into()
}
fn default_cert_key() -> String {
    "keystone-key.pem".into()
}
fn default_ca_cert() -> String {
    "keystone-ca-cert.pem".into()
}
fn default_ca_key() -> String {
    "keystone-ca-key.pem".into()
}
fn default_payload_secret() -> String {
    "payload.secret".into()
}

/// Anchor config-relative paths at the workspace root so xtask behaves
/// the same regardless of the caller's CWD. Explicit `--out` paths stay
/// CWD-relative — that's what the user typed.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives at <workspace>/xtask")
        .to_path_buf()
}

fn load_config() -> Result<Config> {
    let path = workspace_root().join("xtask.toml");
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(toml::from_str(&text)?)
}

fn run(cmd: &mut Command) -> Result<()> {
    println!("  $ {cmd:?}");
    let status = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        bail!("command exited {:?}: {:?}", status.code(), cmd);
    }
    Ok(())
}

/// Write a secret file, refusing to clobber an existing one unless the
/// caller passed --force. A keyfile overwrite silently invalidates every
/// signature a client has pinned, so it must be a deliberate act.
///
/// Secrets are locked to the current user: created mode-0600 on Unix,
/// then `restrict_to_owner` runs unconditionally because truncating an
/// existing file keeps its old permissions (and does the whole job on
/// Windows, where files just inherit the directory ACL).
fn write_secret(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists — pass --force to overwrite",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| f.write_all(bytes))
            .with_context(|| format!("writing {}", path.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    if let Err(e) = restrict_to_owner(path) {
        // Fail closed: a secret left world-readable is worse than none.
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// Write a non-secret file (certificates are public — they go to
/// clients and into TLS handshakes, and the server may read them as a
/// different user). Same --force discipline as `write_secret`, no
/// permission lockdown.
fn write_public(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists — pass --force to overwrite",
            path.display()
        );
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Restrict `path` to the current user. Unix is a chmod; Windows has no
/// mode bits, so we shell out to icacls. Two invocations because /reset
/// refuses to combine with other operations: first /reset drops any
/// explicit ACEs (matters on --force overwrites), then /inheritance:r
/// drops inherited ones and a single grant leaves only the current
/// user with access.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {}", path.display()))
}

#[cfg(windows)]
fn restrict_to_owner(path: &Path) -> Result<()> {
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(domain), Ok(name)) => format!("{domain}\\{name}"),
        (_, Ok(name)) => name,
        _ => bail!("USERNAME unset — cannot ACL {}", path.display()),
    };
    let icacls = |args: &[&str]| -> Result<()> {
        let out = Command::new("icacls")
            .arg(path)
            .args(args)
            .output()
            .context("spawning icacls")?;
        anyhow::ensure!(
            out.status.success(),
            "icacls {args:?} failed on {}: {}{}",
            path.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    };
    icacls(&["/reset"])?;
    icacls(&["/inheritance:r", "/grant:r", &format!("{user}:F")])
}

#[cfg(not(any(unix, windows)))]
fn restrict_to_owner(_path: &Path) -> Result<()> {
    Ok(())
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

// ---- commands -----------------------------------------------------

/// `keygen [--out <path>] [--key-id <n>] [--force]` — mint the issuer seed and print the
/// `(key_id, pubkey)` pair clients bake into `TrustedIssuers`; the seed itself is never printed
/// because scrollback, shell history, and CI logs are all leak paths, and `--key-id` (default 1,
/// read back by the server as KEYSTONE_KEY_ID) is what lets clients hold several trusted keys and
/// revoke one without dropping the rest.
fn cmd_keygen(out: Option<PathBuf>, key_id: u8, force: bool) -> Result<()> {
    let path = match out {
        Some(p) => p,
        None => workspace_root().join(load_config()?.paths.keyfile),
    };

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    write_secret(&path, &seed, force)?;

    let pubkey = hex::encode(Issuer::from_seed(&seed, key_id).verifying_key().to_bytes());
    println!("wrote 32-byte issuer seed to {}", path.display());
    println!();
    println!("  key id:        {key_id}");
    println!("  verifying key (embed in clients as TrustedIssuers entry ({key_id}, pubkey)):");
    println!("    {pubkey}");
    println!();
    println!(
        "  the server reads the keyfile via KEYSTONE_KEYFILE={}",
        path.display()
    );
    println!("  and the key id via KEYSTONE_KEY_ID={key_id}");
    Ok(())
}

/// Parse a `--key-id` value: a u8, default 1 when absent.
fn parse_key_id(raw: Option<String>) -> Result<u8> {
    match raw {
        None => Ok(1),
        Some(s) => s
            .trim()
            .parse::<u8>()
            .with_context(|| format!("--key-id must be 0-255, got {s:?}")),
    }
}

/// KEYSTONE_PAYLOAD_EPOCH for `seal` — same env the server reads. Every
/// artifact key is derived over the epoch, so bumping it (after a
/// secret rotation) makes every previously sealed blob unopenable until
/// resealed. Default 0.
fn load_payload_epoch() -> Result<u32> {
    match std::env::var("KEYSTONE_PAYLOAD_EPOCH") {
        Err(_) => Ok(0),
        Ok(s) => s
            .trim()
            .parse::<u32>()
            .with_context(|| format!("KEYSTONE_PAYLOAD_EPOCH must be a u32, got {s:?}")),
    }
}

/// Load the keystone CA (cert params + key pair) from the configured
/// PEM paths. `None` when either file is missing — callers decide
/// whether that means "fall back" (server cert) or "fail" (client
/// issuance, which has no self-signed fallback).
fn load_ca(cfg: &Config) -> Result<Option<(rcgen::CertificateParams, rcgen::KeyPair)>> {
    let root = workspace_root();
    load_ca_paths(
        &root.join(&cfg.paths.ca_cert),
        &root.join(&cfg.paths.ca_key),
    )
}

/// Load CA material from explicit paths — the env-overridable variant
/// of `load_ca` for commands that honor KEYSTONE_CA_CERT/KEYSTONE_CA_KEY.
fn load_ca_paths(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Option<(rcgen::CertificateParams, rcgen::KeyPair)>> {
    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }
    let cert_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;
    let params =
        rcgen::CertificateParams::from_ca_cert_pem(&cert_pem).context("parsing CA certificate")?;
    let key_pair = rcgen::KeyPair::from_pem(&key_pem).context("parsing CA key")?;
    Ok(Some((params, key_pair)))
}

/// Sign a client-auth certificate with CN = `account` under the
/// keystone CA. Shared by `issue-cert` and `account cert` so both mint
/// certs the server's mTLS check accepts identically.
fn sign_client_cert(
    ca_params: &rcgen::CertificateParams,
    ca_key: &rcgen::KeyPair,
    account: &str,
) -> Result<(rcgen::Certificate, rcgen::KeyPair)> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, account.to_string());
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key_pair = rcgen::KeyPair::generate()?;
    let ca_cert = ca_params.clone().self_signed(ca_key)?;
    let cert = params
        .signed_by(&key_pair, &ca_cert, ca_key)
        .context("signing client cert with CA")?;
    Ok((cert, key_pair))
}

/// `ca [--force]` — generate the keystone CA: a self-signed root that
/// signs the server cert and every per-account client cert. Both PEMs
/// land at the configured paths; overwriting is refused without
/// --force because a new CA invalidates every cert it ever signed.
fn cmd_ca(force: bool) -> Result<()> {
    let cfg = load_config()?;
    let root = workspace_root();
    let cert_path = root.join(&cfg.paths.ca_cert);
    let key_path = root.join(&cfg.paths.ca_key);

    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "keystone-ca");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params
        .self_signed(&key_pair)
        .context("generating CA cert")?;

    write_public(&cert_path, cert.pem().as_bytes(), force)?;
    write_secret(&key_path, key_pair.serialize_pem().as_bytes(), force)?;

    println!("wrote CA certificate to {}", cert_path.display());
    println!("wrote CA private key to {}", key_path.display());
    println!();
    println!(
        "  KEYSTONE_CA_CERT={}  (enables mTLS on the server)",
        cert_path.display()
    );
    println!("  `cargo xtask cert` now signs the server cert with this CA;");
    println!("  `cargo xtask issue-cert <account>` mints client certs.");
    Ok(())
}

/// `cert [--host <name>] [--force]` — TLS cert for the server. When a
/// keystone CA exists the cert is CA-signed (required for mTLS
/// deployments); otherwise it falls back to self-signed with a
/// warning. SANs cover localhost/127.0.0.1 plus any --host value.
/// Prints the leaf SPKI sha256 — the value clients pin.
fn cmd_cert(extra_host: Option<String>, force: bool) -> Result<()> {
    let cfg = load_config()?;
    let root = workspace_root();
    let cert_path = root.join(&cfg.paths.cert);
    let key_path = root.join(&cfg.paths.cert_key);

    let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    if let Some(h) = extra_host {
        sans.push(h);
    }

    let (cert, key_pem, ca_signed) = match load_ca(&cfg)? {
        Some((ca_params, ca_key)) => {
            let mut params = rcgen::CertificateParams::new(sans.clone())?;
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "localhost");
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            let key_pair = rcgen::KeyPair::generate()?;
            let ca_cert = ca_params.self_signed(&ca_key)?;
            let cert = params
                .signed_by(&key_pair, &ca_cert, &ca_key)
                .context("signing server cert with CA")?;
            (cert, key_pair.serialize_pem(), true)
        }
        None => {
            eprintln!(
                "warning: no keystone CA found — generating a SELF-SIGNED cert.\n\
                 mTLS deployments need `cargo xtask ca` first."
            );
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(sans.clone())
                    .context("generating self-signed cert")?;
            (cert, key_pair.serialize_pem(), false)
        }
    };

    write_public(&cert_path, cert.pem().as_bytes(), force)?;
    write_secret(&key_path, key_pem.as_bytes(), force)?;

    // The SPKI pin is what clients actually verify — print it so it
    // can be baked into builds alongside the pinned issuer key.
    let ee = webpki::EndEntityCert::try_from(cert.der())
        .map_err(|e| anyhow::anyhow!("parsing generated cert: {e}"))?;
    let spki_sha256 = hex::encode(Sha256::digest(ee.subject_public_key_info()));

    println!("wrote certificate to {}", cert_path.display());
    println!("wrote private key to {}", key_path.display());
    println!("  SANs: {}", sans.join(", "));
    println!(
        "  signed by: {}",
        if ca_signed {
            "keystone CA"
        } else {
            "self (no CA found)"
        }
    );
    println!("  server SPKI sha256 (client pin): {spki_sha256}");
    println!();
    println!("NOTE: keystone-server serves TLS when KEYSTONE_TLS_CERT and");
    println!("KEYSTONE_TLS_KEY point at these PEMs — `cargo xtask dev` sets");
    println!("them automatically. Clients pin the SPKI hash above.");
    Ok(())
}

/// `issue-cert <account> [--force]` — sign a client certificate for
/// `account` (CN = account name) with the keystone CA. Writes
/// `<account>-cert.pem` + `<account>-key.pem` at the workspace root
/// and prints the cert-DER sha256 — the value for the account's
/// `cert_sha256` field.
fn cmd_issue_cert(account: Option<String>, force: bool) -> Result<()> {
    let account = account.context("usage: cargo xtask issue-cert <account>")?;
    let cfg = load_config()?;
    let root = workspace_root();
    let Some((ca_params, ca_key)) = load_ca(&cfg)? else {
        bail!(
            "no keystone CA at {}/{} — run `cargo xtask ca` first",
            cfg.paths.ca_cert,
            cfg.paths.ca_key
        );
    };
    let (cert, key_pair) = sign_client_cert(&ca_params, &ca_key, &account)?;

    let cert_path = root.join(format!("{account}-cert.pem"));
    let key_path = root.join(format!("{account}-key.pem"));
    write_public(&cert_path, cert.pem().as_bytes(), force)?;
    write_secret(&key_path, key_pair.serialize_pem().as_bytes(), force)?;

    let cert_sha256 = hex::encode(Sha256::digest(cert.der().as_ref()));
    println!("wrote client certificate to {}", cert_path.display());
    println!("wrote client private key to {}", key_path.display());
    println!("  CN: {account}");
    println!("  cert sha256 (account cert_sha256 field): {cert_sha256}");
    Ok(())
}

/// `dev` — provision whatever's missing, print the env, run the server.
fn cmd_dev() -> Result<()> {
    let cfg = load_config()?;
    let root = workspace_root();
    let keyfile = root.join(&cfg.paths.keyfile);

    if !keyfile.exists() {
        println!("no keyfile — generating one");
        cmd_keygen(Some(keyfile.clone()), 1, false)?;
    }
    if !root.join(&cfg.paths.cert).exists() || !root.join(&cfg.paths.cert_key).exists() {
        println!("no dev cert — generating one");
        cmd_cert(None, false)?;
    }

    // Fresh token each `dev` run: it's printed for the operator's own
    // /revoke use and never persisted, so rotation is free.
    let admin_token = random_hex(32);
    println!();
    println!("environment for this server run:");
    println!("  KEYSTONE_KEYFILE={}", keyfile.display());
    println!("  KEYSTONE_DEV_SEED=1");
    println!("  KEYSTONE_ADMIN_TOKEN={admin_token}");
    println!("  KEYSTONE_PORT=8443 (default)");
    println!(
        "  KEYSTONE_TLS_CERT={}",
        root.join(&cfg.paths.cert).display()
    );
    println!(
        "  KEYSTONE_TLS_KEY={}",
        root.join(&cfg.paths.cert_key).display()
    );
    let ca_cert = root.join(&cfg.paths.ca_cert);
    let mtls = ca_cert.exists();
    if mtls {
        println!("  KEYSTONE_CA_CERT={} (mTLS on)", ca_cert.display());
    }
    println!();
    let accounts_file = root.join("accounts.json");
    if accounts_file.exists() {
        println!("  KEYSTONE_ACCOUNTS={}", accounts_file.display());
        println!();
        println!(
            "accounts: file-backed ({}); dev seed is the fallback only",
            accounts_file.display()
        );
    } else {
        println!();
        println!("dev accounts: dev/devpass (product \"dev-product\"), nogrant");
    }
    println!();

    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("-p")
        .arg("keystone-server")
        .current_dir(&root)
        .env("KEYSTONE_KEYFILE", &keyfile)
        .env("KEYSTONE_DEV_SEED", "1")
        .env("KEYSTONE_ADMIN_TOKEN", &admin_token)
        .env("KEYSTONE_TLS_CERT", root.join(&cfg.paths.cert))
        .env("KEYSTONE_TLS_KEY", root.join(&cfg.paths.cert_key));
    if mtls {
        cmd.env("KEYSTONE_CA_CERT", &ca_cert);
    }
    run(&mut cmd)
}

/// `deploy` — release build, then scp binary + keyfile to the target.
fn cmd_deploy() -> Result<()> {
    let cfg = load_config()?;
    let root = workspace_root();
    let keyfile = root.join(&cfg.paths.keyfile);
    if !keyfile.exists() {
        bail!(
            "{} missing — run `cargo xtask keygen` first",
            keyfile.display()
        );
    }

    run(Command::new("cargo")
        .args(["build", "--release", "-p", "keystone-server"])
        .current_dir(&root))?;

    let binary = root
        .join("target")
        .join("release")
        .join(format!("keystone-server{}", std::env::consts::EXE_SUFFIX));
    if !binary.exists() {
        bail!("expected build artifact {}", binary.display());
    }

    let remote = format!("{}@{}", cfg.target.username, cfg.target.host);
    // remote_path is a directory: both the binary and the keyfile land in it.
    run(Command::new("ssh")
        .arg(&remote)
        .arg(format!("mkdir -p {}", cfg.deploy.remote_path)))?;
    run(Command::new("scp")
        .arg(&binary)
        .arg(&keyfile)
        .arg(format!("{remote}:{}/", cfg.deploy.remote_path)))?;
    println!(
        "deployed {} and {} to {remote}:{}/",
        binary.display(),
        keyfile.display(),
        cfg.deploy.remote_path
    );
    Ok(())
}

/// `verify` — preflight checklist. Warnings are states the server
/// tolerates (ephemeral key, closed /revoke); failures block a real run.
fn cmd_verify() -> Result<()> {
    let cfg = load_config()?;
    let root = workspace_root();
    let mut failures = 0u32;

    let mut check = |ok: Option<bool>, label: &str, detail: &str| match ok {
        Some(true) => println!("  [ok]   {label} — {detail}"),
        Some(false) => println!("  [warn] {label} — {detail}"),
        None => {
            println!("  [FAIL] {label} — {detail}");
            failures += 1;
        }
    };

    println!("keystone preflight:");

    // Issuer key material. The key id is what the server will stamp
    // into every signed envelope — surface it so the operator can
    // confirm it matches what clients were built to trust.
    let key_id = match std::env::var("KEYSTONE_KEY_ID") {
        Err(_) => 1u8,
        Ok(s) => match s.trim().parse::<u8>() {
            Ok(n) => n,
            Err(_) => {
                check(None, "KEYSTONE_KEY_ID", &format!("{s:?} is not a u8"));
                1
            }
        },
    };
    let keyfile = root.join(&cfg.paths.keyfile);
    match std::fs::read(&keyfile) {
        Ok(bytes) if bytes.len() == 32 => {
            let seed: &[u8; 32] = bytes.as_slice().try_into().unwrap();
            let pubkey = hex::encode(Issuer::from_seed(seed, key_id).verifying_key().to_bytes());
            check(
                Some(true),
                "keyfile",
                &format!("{} (key id {key_id}, pubkey {pubkey})", keyfile.display()),
            );
        }
        Ok(bytes) => check(
            None,
            "keyfile",
            &format!(
                "{} is {} bytes, expected 32",
                keyfile.display(),
                bytes.len()
            ),
        ),
        Err(_) => check(
            None,
            "keyfile",
            &format!("{} missing — run `cargo xtask keygen`", keyfile.display()),
        ),
    }

    // Production posture: the server refuses plain HTTP and TLS-without-
    // mTLS unless KEYSTONE_ALLOW_INSECURE=1. That flag is for local dev
    // only — its presence in a deploy environment is a misconfiguration.
    match std::env::var("KEYSTONE_ALLOW_INSECURE") {
        Ok(v) if v.trim() == "1" => check(
            Some(false),
            "KEYSTONE_ALLOW_INSECURE",
            "set — server will accept plain HTTP / no-mTLS; unset before deploying",
        ),
        _ => check(
            Some(true),
            "KEYSTONE_ALLOW_INSECURE",
            "unset (mTLS required)",
        ),
    }

    // Payload epoch: must parse, and the operator should know which
    // epoch the sealed artifacts on disk were produced under.
    match load_payload_epoch() {
        Ok(e) => check(Some(true), "KEYSTONE_PAYLOAD_EPOCH", &format!("{e}")),
        Err(e) => check(None, "KEYSTONE_PAYLOAD_EPOCH", &e.to_string()),
    }

    // Dev TLS material.
    for (label, path, marker) in [
        (
            "cert",
            cfg.paths.cert.as_str(),
            "-----BEGIN CERTIFICATE-----",
        ),
        ("cert key", cfg.paths.cert_key.as_str(), "-----BEGIN"),
    ] {
        let full = root.join(path);
        match std::fs::read_to_string(&full) {
            Ok(text) if text.contains(marker) && text.contains("-----END") => {
                check(Some(true), label, &format!("{} (PEM)", full.display()));
            }
            Ok(_) => check(None, label, &format!("{} is not PEM", full.display())),
            Err(_) => check(
                None,
                label,
                &format!("{} missing — run `cargo xtask cert`", full.display()),
            ),
        }
    }

    // Environment the server reads.
    match (
        std::env::var("KEYSTONE_KEYFILE"),
        std::env::var("KEYSTONE_SEED"),
    ) {
        (Ok(p), _) => check(Some(true), "KEYSTONE_KEYFILE", &p),
        (Err(_), Ok(_)) => check(Some(true), "KEYSTONE_SEED", "set (hex seed)"),
        (Err(_), Err(_)) => check(
            Some(false),
            "issuer env",
            "neither KEYSTONE_KEYFILE nor KEYSTONE_SEED set — server will use an ephemeral key",
        ),
    }
    check(
        Some(std::env::var("KEYSTONE_ADMIN_TOKEN").is_ok()),
        "KEYSTONE_ADMIN_TOKEN",
        if std::env::var("KEYSTONE_ADMIN_TOKEN").is_ok() {
            "set — /revoke enabled"
        } else {
            "unset — /revoke will be closed"
        },
    );
    // The real backend is the local accounts file; the stub is the
    // dev-only fallback. Neither configured means the server refuses
    // to start — a FAIL, not a warning.
    let accounts_file = std::env::var_os("KEYSTONE_ACCOUNTS")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("accounts.json"));
    let dev_seed = std::env::var("KEYSTONE_DEV_SEED").as_deref() == Ok("1");
    check(
        if accounts_file.exists() || dev_seed {
            Some(true)
        } else {
            None
        },
        "entitlement backend",
        &if accounts_file.exists() {
            format!("accounts file {}", accounts_file.display())
        } else if dev_seed {
            "KEYSTONE_DEV_SEED=1 — stub dev accounts".to_string()
        } else {
            "no accounts file and KEYSTONE_DEV_SEED unset — server will refuse to start".to_string()
        },
    );

    if failures > 0 {
        bail!("{failures} preflight check(s) failed");
    }
    println!("all checks passed");
    Ok(())
}

/// `seal --product X --version Y --in <file> --out <dir> [--build-id <id>]`
/// — encrypt a release artifact into the payload dir as
/// `{product}-{version}.bin`.
///
/// The artifact secret comes from KEYSTONE_PAYLOAD_SECRET (hex) or
/// KEYSTONE_PAYLOAD_SECRET_FILE (raw 32 bytes), and the epoch from
/// KEYSTONE_PAYLOAD_EPOCH (default 0) — the same env the server reads,
/// so a sealed artifact is always one the server can attest. Rotating
/// the secret means bumping the epoch and resealing every artifact; a
/// blob sealed under the old epoch is simply unopenable afterwards.
/// The plaintext never lands in the payload dir.
///
/// The build id is the per-release watermark: it lands in a
/// `{product}-{version}.build` sidecar the server stamps into every
/// signed manifest and download record. Default is a random 16-hex id
/// so every seal is attributable even when the operator doesn't name it.
/// A `{product}-{version}.sha256` sidecar carries the hex sha256 of the
/// PLAINTEXT artifact so the server can hash-check without decrypting.
fn cmd_seal(
    product: Option<String>,
    version: Option<String>,
    input: Option<String>,
    out_dir: Option<String>,
    build_id: Option<String>,
) -> Result<()> {
    let (product, version, input, out_dir) = match (product, version, input, out_dir) {
        (Some(p), Some(v), Some(i), Some(o)) => (p, v, i, o),
        _ => bail!("seal requires --product, --version, --in, and --out"),
    };
    let secret = load_payload_secret()?;
    let epoch = load_payload_epoch()?;
    let plaintext = std::fs::read(&input).with_context(|| format!("reading {input}"))?;
    anyhow::ensure!(
        plaintext.len() as u64 <= keystone_core::MAX_ARTIFACT_BYTES,
        "{input} exceeds the {}-byte artifact cap",
        keystone_core::MAX_ARTIFACT_BYTES
    );
    // The context must be the length-prefixed form the server derives
    // keys with — "{product}:{version}" is ambiguous AND wrong here:
    // a blob sealed under it can never be opened by artifact_key_for.
    let context = keystone_core::artifact_context(&product, &version, epoch);
    let sealed =
        keystone_core::seal_artifact(&secret, &context, &plaintext).context("sealing artifact")?;
    let dir = PathBuf::from(&out_dir);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {out_dir}"))?;
    let dest = dir.join(format!("{product}-{version}.bin"));
    std::fs::write(&dest, &sealed).with_context(|| format!("writing {}", dest.display()))?;
    let build_id = match build_id {
        Some(id) => {
            anyhow::ensure!(
                !id.is_empty()
                    && id.len() <= 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
                "--build-id must be 1-64 chars of [A-Za-z0-9._-]"
            );
            id
        }
        None => random_hex(8),
    };
    // Sidecar, not embedded: the sealed blob format stays untouched and
    // the server reads the id straight off the filesystem.
    let sidecar = dest.with_extension("build");
    std::fs::write(&sidecar, &build_id)
        .with_context(|| format!("writing {}", sidecar.display()))?;
    // Plaintext hash sidecar: the server can verify/identify the
    // artifact without a per-request decryption pass.
    let sha_sidecar = dest.with_extension("sha256");
    std::fs::write(&sha_sidecar, hex::encode(Sha256::digest(&plaintext)))
        .with_context(|| format!("writing {}", sha_sidecar.display()))?;
    println!(
        "sealed {} ({} bytes) -> {} ({} bytes), build {}, epoch {}",
        input,
        plaintext.len(),
        dest.display(),
        sealed.len(),
        build_id,
        epoch
    );
    Ok(())
}

/// `payload-secret [--out <path>] [--force]` — mint the 32-byte
/// artifact sealing secret as a raw file for
/// KEYSTONE_PAYLOAD_SECRET_FILE. Written owner-only like every other
/// secret; the hex env variant stays for setups that inject it from a
/// secret manager instead of a file.
fn cmd_payload_secret(out: Option<PathBuf>, force: bool) -> Result<()> {
    let path = match out {
        Some(p) => p,
        None => workspace_root().join(load_config()?.paths.payload_secret),
    };
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    write_secret(&path, &secret, force)?;
    println!("wrote 32-byte payload secret to {}", path.display());
    println!("  KEYSTONE_PAYLOAD_SECRET_FILE={}", path.display());
    Ok(())
}

/// The artifact secret for `seal`: KEYSTONE_PAYLOAD_SECRET (64-char
/// hex) or KEYSTONE_PAYLOAD_SECRET_FILE (raw 32 bytes). Mirrors the
/// server's loader — sealing with a secret the server doesn't hold
/// produces artifacts it can never attest.
fn load_payload_secret() -> Result<[u8; 32]> {
    if let Ok(path) = std::env::var("KEYSTONE_PAYLOAD_SECRET_FILE") {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading KEYSTONE_PAYLOAD_SECRET_FILE {path}"))?;
        return bytes
            .as_slice()
            .try_into()
            .context("KEYSTONE_PAYLOAD_SECRET_FILE must contain exactly 32 bytes");
    }
    if let Ok(hex_secret) = std::env::var("KEYSTONE_PAYLOAD_SECRET") {
        let bytes =
            hex::decode(hex_secret.trim()).context("KEYSTONE_PAYLOAD_SECRET must be hex")?;
        return bytes
            .as_slice()
            .try_into()
            .context("KEYSTONE_PAYLOAD_SECRET must decode to exactly 32 bytes");
    }
    bail!("set KEYSTONE_PAYLOAD_SECRET or KEYSTONE_PAYLOAD_SECRET_FILE to seal artifacts")
}

// ---- account management ---------------------------------------------

/// Where the accounts file lives: `--file` wins, then the
/// KEYSTONE_ACCOUNTS env the server reads, then `accounts.json` at the
/// workspace root — matching where `cargo xtask dev` runs the server.
fn accounts_path(args: &[String]) -> Result<PathBuf> {
    if let Some(p) = take_value(args, "--file")? {
        return Ok(PathBuf::from(p));
    }
    if let Ok(p) = std::env::var("KEYSTONE_ACCOUNTS") {
        return Ok(PathBuf::from(p));
    }
    Ok(workspace_root().join("accounts.json"))
}

/// Load the accounts file for mutation. A missing file is an empty
/// table — `account add` creates it. A malformed file is an error:
/// silently starting over would destroy the existing accounts.
fn load_accounts(path: &Path) -> Result<AccountFile> {
    if !path.exists() {
        return Ok(AccountFile::default());
    }
    AccountFile::load(path)
        .map_err(|e| anyhow::anyhow!("{e} — fix or remove it; refusing to clobber"))
}

/// The account name is the first positional arg after the subcommand.
fn account_name(args: &[String], sub: &str) -> Result<String> {
    match args.first() {
        Some(name) if !name.starts_with("--") => Ok(name.clone()),
        _ => bail!("usage: cargo xtask account {sub} <name> [flags]"),
    }
}

/// `account add <name> [--secret <s>]` — create an account. Without
/// --secret the operator is prompted with echo off (a piped stdin is
/// read directly — there's nothing to echo anyway). --secret stays for
/// scripting but leaks via argv: ps, shell history, CI logs.
///
/// The secret is argon2-hashed before it touches disk; plaintext never
/// lands in the file. Refuses to clobber an existing account — a silent
/// overwrite would orphan every cert and grant bound to the old record.
fn account_add(args: &[String]) -> Result<()> {
    let name = account_name(args, "add")?;
    let secret = match take_value(args, "--secret")? {
        Some(s) => {
            eprintln!("warning: --secret leaks via argv (ps, shell history) — prefer the prompt");
            s
        }
        None => prompt_secret(&name)?,
    };
    anyhow::ensure!(!secret.is_empty(), "account secret must not be empty");
    let path = accounts_path(args)?;
    let mut file = load_accounts(&path)?;
    anyhow::ensure!(
        !file.accounts.iter().any(|a| a.name == name),
        "account {name} already exists in {}",
        path.display()
    );
    let salt = SaltString::generate(&mut OsRng);
    let secret_hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing secret: {e}"))?
        .to_string();
    file.accounts.push(AccountRecord {
        name: name.clone(),
        secret_hash,
        entitlements: vec![],
        cert_sha256: None,
    });
    file.save(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("added account {name} to {}", path.display());
    Ok(())
}

/// Read an account secret without it landing in argv. On a real
/// terminal rpassword disables echo and asks twice so a typo can't mint
/// an unusable account; piped stdin is read verbatim (no echo to hide,
/// and it keeps `account add` scriptable without --secret).
fn prompt_secret(name: &str) -> Result<String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading account secret from stdin")?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }
    let first = rpassword::prompt_password(format!("secret for {name}: "))
        .context("reading account secret")?;
    let second =
        rpassword::prompt_password("confirm secret: ").context("reading account secret")?;
    anyhow::ensure!(first == second, "secrets did not match");
    Ok(first)
}

/// `account grant <name> --product <p> --days <n> [--features a,b,c]` —
/// attach a product grant. Re-granting the same product replaces the
/// grant — that's how an operator extends a subscription.
fn account_grant(args: &[String]) -> Result<()> {
    let name = account_name(args, "grant")?;
    let product = take_value(args, "--product")?.context("account grant requires --product <p>")?;
    let days: i64 = take_value(args, "--days")?
        .context("account grant requires --days <n>")?
        .parse()
        .context("--days must be an integer")?;
    // A non-positive grant is born expired — writing it would look like
    // a grant while authorizing nothing. Reject it as an operator error.
    anyhow::ensure!(days > 0, "--days must be positive, got {days}");
    let features = take_value(args, "--features")?
        .map(|f| {
            f.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let path = accounts_path(args)?;
    let mut file = load_accounts(&path)?;
    let record = file
        .accounts
        .iter_mut()
        .find(|a| a.name == name)
        .with_context(|| format!("no account {name} in {}", path.display()))?;
    let expires_at = Utc::now() + chrono::Duration::days(days);
    record.entitlements.retain(|g| g.product != product);
    record.entitlements.push(AccountGrant {
        product: product.clone(),
        expires_at,
        features,
    });
    file.save(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("granted {name} {product} until {}", expires_at.to_rfc3339());
    Ok(())
}

/// `account revoke <name> --product <p>` — remove a grant. Fails loudly
/// when the grant doesn't exist: a silent no-op would let an operator
/// believe access was cut when nothing changed.
fn account_revoke(args: &[String]) -> Result<()> {
    let name = account_name(args, "revoke")?;
    let product =
        take_value(args, "--product")?.context("account revoke requires --product <p>")?;
    let path = accounts_path(args)?;
    let mut file = load_accounts(&path)?;
    let record = file
        .accounts
        .iter_mut()
        .find(|a| a.name == name)
        .with_context(|| format!("no account {name} in {}", path.display()))?;
    let before = record.entitlements.len();
    record.entitlements.retain(|g| g.product != product);
    anyhow::ensure!(
        record.entitlements.len() < before,
        "account {name} holds no grant for {product}"
    );
    file.save(&path).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("revoked {name}'s grant for {product}");
    Ok(())
}

/// `account list` — names, products, expiry, cert binding. Never the
/// secret hashes: this output is for operators and logs.
fn account_list(args: &[String]) -> Result<()> {
    let path = accounts_path(args)?;
    let file = load_accounts(&path)?;
    if file.accounts.is_empty() {
        println!("no accounts in {}", path.display());
        return Ok(());
    }
    for a in &file.accounts {
        let cert = if a.cert_sha256.is_some() {
            "cert-bound"
        } else {
            "any CA cert"
        };
        println!("{a_name} ({cert})", a_name = a.name);
        for g in &a.entitlements {
            let state = if g.expires_at > Utc::now() {
                "expires"
            } else {
                "EXPIRED"
            };
            println!(
                "  {product} — {state} {exp}  features: {features}",
                product = g.product,
                exp = g.expires_at.to_rfc3339(),
                features = g.features.join(",")
            );
        }
    }
    Ok(())
}

/// `account cert <name> [--force]` — sign a client cert (CN = name)
/// with the keystone CA and record its DER sha256 on the account,
/// binding the account to exactly that certificate. CA paths come from
/// KEYSTONE_CA_CERT/KEYSTONE_CA_KEY, else the configured [paths].
fn account_cert(args: &[String], force: bool) -> Result<()> {
    let name = account_name(args, "cert")?;
    let path = accounts_path(args)?;
    let mut file = load_accounts(&path)?;
    anyhow::ensure!(
        file.accounts.iter().any(|a| a.name == name),
        "no account {name} in {}",
        path.display()
    );

    let cfg = load_config()?;
    let root = workspace_root();
    let ca_cert_path = std::env::var_os("KEYSTONE_CA_CERT")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(&cfg.paths.ca_cert));
    let ca_key_path = std::env::var_os("KEYSTONE_CA_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(&cfg.paths.ca_key));
    let Some((ca_params, ca_key)) = load_ca_paths(&ca_cert_path, &ca_key_path)? else {
        bail!(
            "no keystone CA at {}/{} — cert issuance lands with the mTLS slice \
             (`cargo xtask ca` generates one)",
            ca_cert_path.display(),
            ca_key_path.display()
        );
    };

    let (cert, key_pair) = sign_client_cert(&ca_params, &ca_key, &name)?;
    let cert_path = root.join(format!("{name}-cert.pem"));
    let key_path = root.join(format!("{name}-key.pem"));
    write_public(&cert_path, cert.pem().as_bytes(), force)?;
    write_secret(&key_path, key_pair.serialize_pem().as_bytes(), force)?;

    let cert_sha256 = hex::encode(Sha256::digest(cert.der().as_ref()));
    let record = file
        .accounts
        .iter_mut()
        .find(|a| a.name == name)
        .expect("checked above");
    record.cert_sha256 = Some(cert_sha256.clone());
    file.save(&path).map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("wrote client certificate to {}", cert_path.display());
    println!("wrote client private key to {}", key_path.display());
    println!("  CN: {name}");
    println!("  recorded cert_sha256 {cert_sha256} on account {name}");
    Ok(())
}

/// `account <add|grant|revoke|list|cert> ...` — manage the local
/// accounts file the server reads via KEYSTONE_ACCOUNTS.
fn cmd_account(args: &[String]) -> Result<()> {
    let Some(sub) = args.first() else {
        bail!("usage: cargo xtask account <add|grant|revoke|list|cert> ...");
    };
    let rest = &args[1..];
    let force = rest.iter().any(|a| a == "--force");
    match sub.as_str() {
        "add" => account_add(rest),
        "grant" => account_grant(rest),
        "revoke" => account_revoke(rest),
        "list" => account_list(rest),
        "cert" => account_cert(rest, force),
        _ => bail!("unknown account subcommand {sub}"),
    }
}

// ---- argv plumbing --------------------------------------------------

fn usage() -> ! {
    eprintln!(
        "cargo xtask <command>

  keygen [--out <path>] [--key-id <n>] [--force]
                                    generate issuer seed, print (key_id, pubkey) to pin
  ca [--force]                      generate the keystone CA (signs server + client certs)
  cert [--host <name>] [--force]    server TLS cert (CA-signed when a CA exists)
  issue-cert <account> [--force]    sign a client cert (CN=<account>) with the CA
  payload-secret [--out <path>] [--force]
                                    mint the artifact sealing secret file
  dev                               provision missing secrets, run the server
  deploy                            release build + scp to [target] host
  verify                            preflight checklist
  seal --product X --version Y --in <file> --out <dir> [--build-id <id>]
                                    seal a release artifact into the payload dir
  account <add|grant|revoke|list|cert> [--file <path>] [--force]
                                    manage the local accounts file"
    );
    exit(2);
}

/// Pull a `--flag value` pair out of the arg list, or None.
fn take_value(args: &[String], flag: &str) -> Result<Option<String>> {
    match args.iter().position(|a| a == flag) {
        Some(i) => Ok(Some(
            args.get(i + 1)
                .with_context(|| format!("{flag} requires a value"))?
                .clone(),
        )),
        None => Ok(None),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        usage();
    };
    let rest = &args[1..];
    let force = rest.iter().any(|a| a == "--force");

    match cmd.as_str() {
        "keygen" => cmd_keygen(
            take_value(rest, "--out")?.map(PathBuf::from),
            parse_key_id(take_value(rest, "--key-id")?)?,
            force,
        ),
        "ca" => cmd_ca(force),
        "cert" => cmd_cert(take_value(rest, "--host")?, force),
        "issue-cert" => cmd_issue_cert(rest.iter().find(|a| !a.starts_with("--")).cloned(), force),
        "payload-secret" => {
            cmd_payload_secret(take_value(rest, "--out")?.map(PathBuf::from), force)
        }
        "dev" => cmd_dev(),
        "deploy" => cmd_deploy(),
        "account" => cmd_account(rest),
        "verify" => cmd_verify(),
        "seal" => cmd_seal(
            take_value(rest, "--product")?,
            take_value(rest, "--version")?,
            take_value(rest, "--in")?,
            take_value(rest, "--out")?,
            take_value(rest, "--build-id")?,
        ),
        _ => usage(),
    }
}
