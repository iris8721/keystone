//! Keystone provisioning, sealing, and deploy tasks.
//!
//! Common flow:
//!   cargo xtask dev        (provisions missing material, runs the server)
//!   cargo xtask verify     (preflight checklist)
//!   cargo xtask deploy     (release build + ship to the xtask.toml target host)

use anyhow::{Context, Result, bail, ensure};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use chrono::Utc;
use keystone_core::wire::{
    MAX_ACCOUNT_LEN, MAX_ADMIN_TOKEN_BYTES, MAX_PRODUCT_LEN, MIN_ADMIN_TOKEN_LEN, validate_build_id,
};
use keystone_core::{
    AccountFile, AccountGrant, AccountRecord, ArtifactPaths, Issuer, KEYFILE_LEN,
    SEALED_PREFIX_LEN, revocations, valid_segment,
};
use rand::RngCore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use zeroize::Zeroizing;

const SERVER_BIN: &str = "keystone-server";
const ENV_FILE: &str = "keystone.env";
/// Client certificate name (CN and file stem) for the admin listener.
const ADMIN_CERT_NAME: &str = "keystone-admin";
/// Dev-only accounts, kept apart from the deployed accounts file.
const DEV_ACCOUNTS: &str = "dev-accounts.json";
const DEV_ACCOUNT: &str = "dev";
const DEV_SECRET: &str = "devpass";
const DEV_PRODUCT: &str = "dev-product";

#[derive(Debug, Deserialize)]
struct Config {
    target: Option<TargetCfg>,
    deploy: Option<DeployCfg>,
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
#[serde(default)]
struct PathsCfg {
    keyfile: String,
    cert: String,
    cert_key: String,
    ca_cert: String,
    ca_key: String,
    payload_secret: String,
    payload_dir: String,
    accounts: String,
    revocations: String,
}

impl Default for PathsCfg {
    fn default() -> Self {
        Self {
            keyfile: "keystone-1.key".into(),
            cert: "keystone-cert.pem".into(),
            cert_key: "keystone-key.pem".into(),
            ca_cert: "keystone-ca-cert.pem".into(),
            ca_key: "keystone-ca-key.pem".into(),
            payload_secret: "payload.secret".into(),
            payload_dir: "payloads".into(),
            accounts: "accounts.json".into(),
            revocations: "revoked-keys.json".into(),
        }
    }
}

/// Source tree root; cargo builds run here.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives at <workspace>/xtask")
        .to_path_buf()
}

/// Directory holding xtask.toml and every config-relative path.
fn config_root() -> PathBuf {
    std::env::var_os("XTASK_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(workspace_root)
}

struct Workspace {
    root: PathBuf,
    cfg: Config,
}

impl Workspace {
    fn load() -> Result<Self> {
        let root = config_root();
        let path = root.join("xtask.toml");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg = toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Self { root, cfg })
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// `var` when set (what the server will read), else the configured path.
    fn env_or(&self, var: &str, rel: &str) -> PathBuf {
        std::env::var_os(var)
            .map(PathBuf::from)
            .unwrap_or_else(|| self.path(rel))
    }

    fn ca_paths(&self) -> (PathBuf, PathBuf) {
        (
            self.env_or("KEYSTONE_CA_CERT", &self.cfg.paths.ca_cert),
            self.env_or("KEYSTONE_CA_KEY", &self.cfg.paths.ca_key),
        )
    }
}

fn run(cmd: &mut Command) -> Result<()> {
    println!("  $ {cmd:?}");
    let status = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        bail!("command exited {:?}: {:?}", status.code(), cmd);
    }
    Ok(())
}

fn refuse_clobber(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists — pass --force to overwrite",
            path.display()
        );
    }
    Ok(())
}

/// Write an owner-only secret file atomically; refuses to clobber without `force`.
fn write_secret(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    refuse_clobber(path, force)?;
    keystone_core::fs::write_owner_only_atomic(path, bytes)
        .with_context(|| format!("writing {}", path.display()))
}

/// Write a public file (certificates); refuses to clobber without `force`.
fn write_public(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    refuse_clobber(path, force)?;
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

/// Replace a public file via a sibling temp file so readers never see a partial write.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

fn random_hex(bytes: usize) -> Zeroizing<String> {
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    rand::thread_rng().fill_bytes(&mut buf);
    Zeroizing::new(hex::encode(&*buf))
}

/// Single-quote for a POSIX remote shell.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn read_issuer(path: &Path) -> Result<Issuer> {
    let bytes =
        Zeroizing::new(std::fs::read(path).with_context(|| format!("reading {}", path.display()))?);
    Issuer::from_keyfile(&bytes).with_context(|| {
        format!(
            "{} is not a {KEYFILE_LEN}-byte keyfile (key id || seed) — regenerate with `cargo xtask keygen`",
            path.display()
        )
    })
}

fn pubkey_hex(issuer: &Issuer) -> String {
    hex::encode(issuer.verifying_key().to_bytes())
}

/// Revoked key ids from `KEYSTONE_REVOKED_KEY_IDS` (comma-separated u8 list).
fn env_revoked_key_ids() -> Result<BTreeSet<u8>> {
    let Ok(raw) = std::env::var("KEYSTONE_REVOKED_KEY_IDS") else {
        return Ok(BTreeSet::new());
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<u8>()
                .with_context(|| format!("KEYSTONE_REVOKED_KEY_IDS: {s:?} is not a u8"))
        })
        .collect()
}

/// Revoked key ids persisted by the server. Missing file = none.
fn load_revocations(path: &Path) -> Result<BTreeSet<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            revocations::parse(&bytes).with_context(|| format!("parsing {}", path.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn check_admin_token(token: &str) -> Result<()> {
    let chars = token.chars().count();
    ensure!(
        chars >= MIN_ADMIN_TOKEN_LEN,
        "KEYSTONE_ADMIN_TOKEN is {chars} characters; the server requires at least {MIN_ADMIN_TOKEN_LEN}"
    );
    ensure!(
        token.len() <= MAX_ADMIN_TOKEN_BYTES,
        "KEYSTONE_ADMIN_TOKEN exceeds {MAX_ADMIN_TOKEN_BYTES} bytes"
    );
    Ok(())
}

/// `KEYSTONE_ADMIN_CERT_SHA256`: comma-separated hex sha256 of admin leaf certificates.
fn parse_admin_cert_hashes(raw: &str) -> Result<BTreeSet<String>> {
    let hashes: BTreeSet<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            ensure!(
                s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()),
                "KEYSTONE_ADMIN_CERT_SHA256: {s:?} is not a hex sha256"
            );
            Ok(s.to_ascii_lowercase())
        })
        .collect::<Result<_>>()?;
    ensure!(
        !hashes.is_empty(),
        "KEYSTONE_ADMIN_CERT_SHA256 lists no certificate"
    );
    Ok(hashes)
}

/// Account names travel in exchange requests and name certificate files.
fn check_account_name(name: &str) -> Result<()> {
    ensure!(
        name.len() <= MAX_ACCOUNT_LEN && valid_segment(name),
        "account name {name:?} must be at most {MAX_ACCOUNT_LEN} bytes of [A-Za-z0-9._-], \
         without a leading or trailing dot or a reserved device name"
    );
    Ok(())
}

fn check_product(product: &str) -> Result<()> {
    ensure!(
        product.len() <= MAX_PRODUCT_LEN && valid_segment(product),
        "product {product:?} must be at most {MAX_PRODUCT_LEN} bytes of [A-Za-z0-9._-], \
         without a leading or trailing dot or a reserved device name"
    );
    Ok(())
}

/// `keygen --key-id N [--out P] [--force]`: write a keyfile and print the
/// (key id, pubkey) pair clients trust; the seed is never printed.
fn cmd_keygen(key_id: u8, out: Option<PathBuf>, force: bool) -> Result<()> {
    let path = out.unwrap_or_else(|| config_root().join(format!("keystone-{key_id}.key")));
    let issuer = Issuer::generate(key_id);
    write_secret(&path, issuer.keyfile_bytes().as_slice(), force)?;
    let pubkey = pubkey_hex(&issuer);
    println!("wrote {KEYFILE_LEN}-byte keyfile to {}", path.display());
    println!("  key id:        {key_id}");
    println!("  verifying key: {pubkey}");
    println!("  clients trust ({key_id}, {pubkey}) via TrustedIssuers");
    println!("  server: KEYSTONE_KEYFILE={}", path.display());
    Ok(())
}

fn parse_key_id(raw: Option<String>) -> Result<u8> {
    let raw = raw.context("keygen requires --key-id <0-255>")?;
    raw.trim()
        .parse::<u8>()
        .with_context(|| format!("--key-id must be 0-255, got {raw:?}"))
}

fn load_ca_paths(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Option<(rcgen::CertificateParams, rcgen::KeyPair)>> {
    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }
    let cert_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?;
    let key_pem = Zeroizing::new(
        std::fs::read_to_string(key_path)
            .with_context(|| format!("reading {}", key_path.display()))?,
    );
    let params =
        rcgen::CertificateParams::from_ca_cert_pem(&cert_pem).context("parsing CA certificate")?;
    let key_pair = rcgen::KeyPair::from_pem(&key_pem).context("parsing CA key")?;
    Ok(Some((params, key_pair)))
}

/// sha256 of a certificate's DER SubjectPublicKeyInfo: the value clients pin.
fn cert_spki_sha256(der: &CertificateDer<'_>) -> Result<String> {
    let ee = webpki::EndEntityCert::try_from(der)
        .map_err(|e| anyhow::anyhow!("parsing certificate: {e}"))?;
    Ok(hex::encode(Sha256::digest(ee.subject_public_key_info())))
}

fn key_spki_sha256(key: &rcgen::KeyPair) -> String {
    hex::encode(Sha256::digest(key.public_key_der()))
}

/// `ca [--force]`: self-signed root that signs the server cert and every client cert.
fn cmd_ca(force: bool) -> Result<()> {
    let ws = Workspace::load()?;
    let cert_path = ws.path(&ws.cfg.paths.ca_cert);
    let key_path = ws.path(&ws.cfg.paths.ca_key);

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

    refuse_clobber(&key_path, force)?;
    write_public(&cert_path, cert.pem().as_bytes(), force)?;
    write_secret(
        &key_path,
        Zeroizing::new(key_pair.serialize_pem()).as_bytes(),
        force,
    )?;

    println!("wrote CA certificate to {}", cert_path.display());
    println!("wrote CA private key to {}", key_path.display());
    println!("  KEYSTONE_CA_CERT={}  (enables mTLS)", cert_path.display());
    Ok(())
}

enum KeySource {
    /// Reuse the configured server key, generating one only when absent.
    Existing,
    File(PathBuf),
    New,
}

/// `cert [--host H]... [--key P | --new-key] [--force]`: server TLS cert,
/// CA-signed when a CA exists. The key (and so the client SPKI pin)
/// survives re-issue; replacing an existing key requires `--force`.
fn cmd_cert(ws: &Workspace, hosts: &[String], source: KeySource, force: bool) -> Result<()> {
    let cert_path = ws.path(&ws.cfg.paths.cert);
    let key_path = ws.path(&ws.cfg.paths.cert_key);

    let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    for host in hosts {
        if !sans.contains(host) {
            sans.push(host.clone());
        }
    }

    let read_key = |path: &Path| -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
        ))
    };
    let key_pem = match source {
        KeySource::Existing if key_path.exists() => read_key(&key_path)?,
        KeySource::File(path) => read_key(&path)?,
        KeySource::Existing | KeySource::New => {
            Zeroizing::new(rcgen::KeyPair::generate()?.serialize_pem())
        }
    };
    let key_pair = rcgen::KeyPair::from_pem(&key_pem).context("parsing server private key")?;
    let current = key_path.exists().then(|| read_key(&key_path)).transpose()?;
    let reused = current.as_deref() == Some(&*key_pem);
    if !reused {
        write_secret(&key_path, key_pem.as_bytes(), force)?;
    }

    let mut params = rcgen::CertificateParams::new(sans.clone())?;
    let common_name = hosts.first().map_or("localhost", String::as_str);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let (ca_cert_path, ca_key_path) = ws.ca_paths();
    let (cert, signer) = match load_ca_paths(&ca_cert_path, &ca_key_path)? {
        Some((ca_params, ca_key)) => {
            let ca_cert = ca_params.self_signed(&ca_key)?;
            let cert = params
                .signed_by(&key_pair, &ca_cert, &ca_key)
                .context("signing server cert with CA")?;
            (cert, "keystone CA")
        }
        None => {
            eprintln!(
                "warning: no keystone CA — generating a SELF-SIGNED cert; mTLS needs `cargo xtask ca` first"
            );
            let cert = params
                .self_signed(&key_pair)
                .context("generating self-signed cert")?;
            (cert, "self (no CA found)")
        }
    };
    // Public and re-issuable: the pin lives in the key, not the cert.
    write_public(&cert_path, cert.pem().as_bytes(), true)?;

    let spki = cert_spki_sha256(cert.der())?;
    println!("wrote certificate to {}", cert_path.display());
    println!(
        "{} {}",
        if reused {
            "reused private key"
        } else {
            "wrote private key to"
        },
        key_path.display()
    );
    println!("  SANs: {}", sans.join(", "));
    println!("  signed by: {signer}");
    println!("  server SPKI sha256 (client pin): {spki}");
    Ok(())
}

/// `tls-key --out P [--force]`: pre-generate the next server key so clients
/// can pin it before `cert --key P --force` swaps it in.
fn cmd_tls_key(out: Option<PathBuf>, force: bool) -> Result<()> {
    let path = out.context("usage: cargo xtask tls-key --out <path> [--force]")?;
    let key = rcgen::KeyPair::generate()?;
    write_secret(&path, Zeroizing::new(key.serialize_pem()).as_bytes(), force)?;
    println!("wrote server private key to {}", path.display());
    println!("  SPKI sha256 (next client pin): {}", key_spki_sha256(&key));
    Ok(())
}

/// `spki <pem>`: SPKI sha256 of a certificate or private key.
fn cmd_spki(path: Option<&String>) -> Result<()> {
    let path = path.context("usage: cargo xtask spki <pem>")?;
    let text = Zeroizing::new(std::fs::read(path).with_context(|| format!("reading {path}"))?);
    let spki = match CertificateDer::from_pem_slice(&text) {
        Ok(der) => cert_spki_sha256(&der)?,
        Err(_) => {
            let pem = std::str::from_utf8(&text).with_context(|| format!("{path} is not PEM"))?;
            let key = rcgen::KeyPair::from_pem(pem)
                .with_context(|| format!("{path} holds neither a certificate nor a private key"))?;
            key_spki_sha256(&key)
        }
    };
    println!("{spki}");
    Ok(())
}

/// Sign a client-auth cert (CN = account) under the keystone CA, write it
/// beside the config, and return the cert-DER sha256 (the account pin).
fn issue_client_cert(ws: &Workspace, account: &str, force: bool) -> Result<String> {
    check_account_name(account)?;
    let (ca_cert_path, ca_key_path) = ws.ca_paths();
    let Some((ca_params, ca_key)) = load_ca_paths(&ca_cert_path, &ca_key_path)? else {
        bail!(
            "no keystone CA at {} / {} — run `cargo xtask ca` first",
            ca_cert_path.display(),
            ca_key_path.display()
        );
    };
    let cert_path = ws.root.join(format!("{account}-cert.pem"));
    let key_path = ws.root.join(format!("{account}-key.pem"));
    refuse_clobber(&cert_path, force)?;
    refuse_clobber(&key_path, force)?;

    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, account);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key_pair = rcgen::KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let cert = params
        .signed_by(&key_pair, &ca_cert, &ca_key)
        .context("signing client cert with CA")?;

    write_public(&cert_path, cert.pem().as_bytes(), true)?;
    write_secret(
        &key_path,
        Zeroizing::new(key_pair.serialize_pem()).as_bytes(),
        true,
    )?;
    println!("wrote client certificate to {}", cert_path.display());
    println!("wrote client private key to {}", key_path.display());
    println!("  CN: {account}");
    Ok(hex::encode(Sha256::digest(cert.der())))
}

/// `issue-cert <account> [--file P] [--force]`: client cert; the pin is
/// recorded on the account when the accounts file holds it.
fn cmd_issue_cert(args: &[String], force: bool) -> Result<()> {
    let account = positional(
        args,
        "usage: cargo xtask issue-cert <account> [--file <path>]",
    )?;
    let ws = Workspace::load()?;
    let path = accounts_path(args, Some(&ws))?;
    let mut file = path.exists().then(|| load_accounts(&path)).transpose()?;
    let hash = issue_client_cert(&ws, &account, force)?;
    let record = file
        .as_mut()
        .and_then(|f| f.accounts.iter_mut().find(|a| a.name == account));
    match record {
        Some(record) => {
            record.cert_sha256 = Some(hash.clone());
            file.as_ref().expect("record came from file").save(&path)?;
            println!("  pinned on account {account} in {}", path.display());
        }
        None => println!(
            "  account {account} not in {} — pin not recorded",
            path.display()
        ),
    }
    println!("  cert sha256: {hash}");
    Ok(())
}

/// `KEYSTONE_PAYLOAD_EPOCH` (default 0); artifact keys derive over it.
fn load_payload_epoch() -> Result<u32> {
    match std::env::var("KEYSTONE_PAYLOAD_EPOCH") {
        Err(_) => Ok(0),
        Ok(s) => s
            .trim()
            .parse::<u32>()
            .with_context(|| format!("KEYSTONE_PAYLOAD_EPOCH must be a u32, got {s:?}")),
    }
}

fn read_payload_secret(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes =
        Zeroizing::new(std::fs::read(path).with_context(|| format!("reading {}", path.display()))?);
    let secret: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .with_context(|| format!("{} must hold exactly 32 bytes", path.display()))?;
    Ok(Zeroizing::new(secret))
}

/// `payload-secret [--out P] [--force]`: the raw 32-byte artifact secret.
fn cmd_payload_secret(out: Option<PathBuf>, force: bool) -> Result<()> {
    let path = match out {
        Some(p) => p,
        None => {
            let ws = Workspace::load()?;
            ws.path(&ws.cfg.paths.payload_secret)
        }
    };
    let mut secret = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(&mut *secret);
    write_secret(&path, &*secret, force)?;
    println!("wrote 32-byte payload secret to {}", path.display());
    println!("  KEYSTONE_PAYLOAD_SECRET_FILE={}", path.display());
    Ok(())
}

struct SealArgs {
    product: Option<String>,
    version: Option<String>,
    input: Option<String>,
    out_dir: Option<PathBuf>,
    build_id: Option<String>,
}

/// Read an artifact, refusing anything over `MAX_PLAINTEXT_BYTES` before loading it;
/// the read is bounded too, in case the file grows after the size check.
fn read_plaintext(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let cap = keystone_core::MAX_PLAINTEXT_BYTES;
    let too_big = |len: u64| {
        anyhow::anyhow!(
            "{} is {len} bytes; sealed artifacts hold at most {cap} bytes of plaintext",
            path.display()
        )
    };
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let len = file
        .metadata()
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    if len > cap {
        return Err(too_big(len));
    }
    let mut plaintext = Zeroizing::new(Vec::with_capacity(len as usize));
    file.take(cap + 1)
        .read_to_end(&mut plaintext)
        .with_context(|| format!("reading {}", path.display()))?;
    if plaintext.len() as u64 > cap {
        return Err(too_big(plaintext.len() as u64));
    }
    Ok(plaintext)
}

/// `seal`: encrypt an artifact into `{dir}/{product}/{version}.bin` with
/// `.sha256` (hex of the plaintext) and `.build` sidecars, under the
/// secret and epoch the server reads.
fn cmd_seal(args: SealArgs) -> Result<()> {
    let (Some(product), Some(version), Some(input)) = (args.product, args.version, args.input)
    else {
        bail!("seal requires --product, --version, and --in");
    };
    let build_id = match args.build_id {
        Some(id) => {
            validate_build_id(&id).context("--build-id")?;
            id
        }
        None => random_hex(8).to_string(),
    };
    keystone_core::wire::validate_release(&product, &version)
        .context("product and version must be short [A-Za-z0-9._-] names")?;
    let epoch = load_payload_epoch()?;
    let secret_env = std::env::var_os("KEYSTONE_PAYLOAD_SECRET_FILE").map(PathBuf::from);
    let dir_arg = args
        .out_dir
        .or_else(|| std::env::var_os("KEYSTONE_PAYLOAD_DIR").map(PathBuf::from));
    // The config is only consulted for what flags and env leave open.
    let ws = match (&secret_env, &dir_arg) {
        (Some(_), Some(_)) => None,
        _ => Some(Workspace::load()?),
    };
    let from_config = |pick: fn(&PathsCfg) -> &str| {
        let ws = ws.as_ref().expect("loaded when a path is unset");
        ws.path(pick(&ws.cfg.paths))
    };
    let secret_path = secret_env.unwrap_or_else(|| from_config(|p| &p.payload_secret));
    let dir = dir_arg.unwrap_or_else(|| from_config(|p| &p.payload_dir));
    let paths = ArtifactPaths::new(&dir, &product, &version)?;
    let secret = read_payload_secret(&secret_path)?;

    let plaintext = read_plaintext(Path::new(&input))?;
    let context = keystone_core::artifact_context(&product, &version, epoch);
    let sealed =
        keystone_core::seal_artifact(&secret, &context, &plaintext).context("sealing artifact")?;

    let product_dir = paths.sealed.parent().expect("artifact path has a parent");
    std::fs::create_dir_all(product_dir)
        .with_context(|| format!("creating {}", product_dir.display()))?;
    // Sidecars first: the server requires both before it serves the blob.
    write_atomic(
        &paths.sha256,
        hex::encode(Sha256::digest(&*plaintext)).as_bytes(),
    )?;
    write_atomic(&paths.build, build_id.as_bytes())?;
    write_atomic(&paths.sealed, &sealed)?;
    println!(
        "sealed {input} ({} bytes) -> {} ({} bytes), build {build_id}, epoch {epoch}",
        plaintext.len(),
        paths.sealed.display(),
        sealed.len()
    );
    Ok(())
}

/// Every deviation from `{dir}/{product}/{version}.bin` + sidecars, and the artifact count.
fn payload_layout_problems(dir: &Path) -> Result<(usize, Vec<String>)> {
    let mut artifacts = 0;
    let mut problems = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let entry = entry?;
        let product = entry.file_name().to_string_lossy().into_owned();
        if !entry.file_type()?.is_dir() {
            problems.push(format!(
                "{} is not a product directory (layout is <product>/<version>.bin)",
                entry.path().display()
            ));
            continue;
        }
        if !valid_segment(&product) {
            problems.push(format!("invalid product directory {product:?}"));
            continue;
        }
        for file in std::fs::read_dir(entry.path())? {
            let path = file?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }
            artifacts += 1;
            let version = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if keystone_core::wire::validate_release(&product, version).is_err() {
                problems.push(format!("invalid release name {}", path.display()));
                continue;
            }
            let paths = ArtifactPaths::new(dir, &product, version)?;
            if std::fs::metadata(&paths.sealed)?.len() <= SEALED_PREFIX_LEN as u64 {
                problems.push(format!("{} is truncated", paths.sealed.display()));
            }
            match std::fs::read_to_string(&paths.sha256) {
                Ok(h)
                    if h.trim().len() == 64 && h.trim().bytes().all(|b| b.is_ascii_hexdigit()) => {}
                Ok(_) => problems.push(format!("{} is not a hex sha256", paths.sha256.display())),
                Err(_) => problems.push(format!("{} missing", paths.sha256.display())),
            }
            match std::fs::read_to_string(&paths.build) {
                Ok(id) if validate_build_id(id.trim()).is_ok() => {}
                Ok(_) => problems.push(format!("{} is not a build id", paths.build.display())),
                Err(_) => problems.push(format!("{} missing", paths.build.display())),
            }
        }
    }
    Ok((artifacts, problems))
}

#[derive(Default)]
struct Checklist {
    failures: u32,
}

impl Checklist {
    fn ok(&mut self, label: &str, detail: impl AsRef<str>) {
        println!("  [ok]   {label} — {}", detail.as_ref());
    }
    fn warn(&mut self, label: &str, detail: impl AsRef<str>) {
        println!("  [warn] {label} — {}", detail.as_ref());
    }
    fn fail(&mut self, label: &str, detail: impl AsRef<str>) {
        println!("  [FAIL] {label} — {}", detail.as_ref());
        self.failures += 1;
    }
}

/// `verify`: preflight against the environment the server will read.
/// Warnings are tolerated states; failures block a real run.
fn cmd_verify() -> Result<()> {
    let ws = Workspace::load()?;
    let p = &ws.cfg.paths;
    let mut c = Checklist::default();
    let insecure = std::env::var("KEYSTONE_ALLOW_INSECURE").as_deref() == Ok("1");
    println!("keystone preflight:");

    let keyfile = ws.env_or("KEYSTONE_KEYFILE", &p.keyfile);
    let active = match read_issuer(&keyfile) {
        Ok(issuer) => {
            c.ok(
                "keyfile",
                format!(
                    "{} (key id {}, pubkey {})",
                    keyfile.display(),
                    issuer.key_id(),
                    pubkey_hex(&issuer)
                ),
            );
            Some(issuer.key_id())
        }
        Err(e) => {
            c.fail("keyfile", format!("{e:#}"));
            None
        }
    };

    let revocations = ws.env_or("KEYSTONE_REVOCATIONS_FILE", &p.revocations);
    let revoked = match (env_revoked_key_ids(), load_revocations(&revocations)) {
        (Ok(env), Ok(file)) => Some(env.union(&file).copied().collect::<BTreeSet<u8>>()),
        (Err(e), _) | (_, Err(e)) => {
            c.fail("revoked key ids", format!("{e:#}"));
            None
        }
    };
    if let (Some(active), Some(revoked)) = (active, &revoked) {
        if revoked.contains(&active) {
            c.fail(
                "active key",
                format!(
                    "key id {active} is revoked (KEYSTONE_REVOKED_KEY_IDS or {}) — the server refuses to start",
                    revocations.display()
                ),
            );
        } else {
            c.ok(
                "active key",
                format!(
                    "key id {active} not revoked ({} revoked ids)",
                    revoked.len()
                ),
            );
        }
    }

    let admin_token = std::env::var("KEYSTONE_ADMIN_TOKEN")
        .ok()
        .map(Zeroizing::new);
    match &admin_token {
        None => c.warn("KEYSTONE_ADMIN_TOKEN", "unset — admin listener off"),
        Some(token) => match check_admin_token(token) {
            Ok(()) => c.ok("KEYSTONE_ADMIN_TOKEN", "set — admin listener on"),
            Err(e) => c.fail("KEYSTONE_ADMIN_TOKEN", e.to_string()),
        },
    }

    if insecure {
        c.warn(
            "KEYSTONE_ALLOW_INSECURE",
            "set — plain HTTP / no mTLS accepted; unset before deploying",
        );
    } else {
        c.ok("KEYSTONE_ALLOW_INSECURE", "unset (mTLS required)");
    }

    let cert_path = ws.env_or("KEYSTONE_TLS_CERT", &p.cert);
    let key_path = ws.env_or("KEYSTONE_TLS_KEY", &p.cert_key);
    let cert_spki = CertificateDer::from_pem_file(&cert_path)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .and_then(|der| cert_spki_sha256(&der));
    let key_spki = std::fs::read_to_string(&key_path)
        .map(Zeroizing::new)
        .map_err(anyhow::Error::from)
        .and_then(|pem| Ok(key_spki_sha256(&rcgen::KeyPair::from_pem(&pem)?)));
    match (cert_spki, key_spki) {
        (Ok(cert), Ok(key)) if cert == key => c.ok(
            "TLS cert/key",
            format!("{} (SPKI sha256 {cert})", cert_path.display()),
        ),
        (Ok(_), Ok(_)) => c.fail(
            "TLS cert/key",
            format!(
                "{} does not match {}",
                key_path.display(),
                cert_path.display()
            ),
        ),
        (Err(e), _) => c.fail(
            "TLS cert",
            format!("{}: {e} — run `cargo xtask cert`", cert_path.display()),
        ),
        (_, Err(e)) => c.fail(
            "TLS key",
            format!("{}: {e} — run `cargo xtask cert`", key_path.display()),
        ),
    }
    let ca_cert = ws.env_or("KEYSTONE_CA_CERT", &p.ca_cert);
    let mtls = match CertificateDer::from_pem_file(&ca_cert) {
        Ok(_) => {
            c.ok("CA cert", format!("{} (mTLS on)", ca_cert.display()));
            true
        }
        Err(e) if insecure => {
            c.warn("CA cert", format!("{}: {e} — mTLS off", ca_cert.display()));
            false
        }
        Err(e) => {
            c.fail(
                "CA cert",
                format!(
                    "{}: {e} — the server requires mTLS; run `cargo xtask ca`",
                    ca_cert.display()
                ),
            );
            false
        }
    };

    match std::env::var("KEYSTONE_ADMIN_CERT_SHA256") {
        Ok(raw) => match parse_admin_cert_hashes(&raw) {
            Ok(hashes) => c.ok(
                "KEYSTONE_ADMIN_CERT_SHA256",
                format!("{} admin certificate(s)", hashes.len()),
            ),
            Err(e) => c.fail("KEYSTONE_ADMIN_CERT_SHA256", e.to_string()),
        },
        Err(_) if admin_token.is_some() && mtls => c.fail(
            "KEYSTONE_ADMIN_CERT_SHA256",
            format!(
                "unset — required for the admin listener under mTLS; \
                 run `cargo xtask issue-cert {ADMIN_CERT_NAME}` and list its sha256"
            ),
        ),
        Err(_) => c.ok("KEYSTONE_ADMIN_CERT_SHA256", "not needed"),
    }

    let accounts = ws.env_or("KEYSTONE_ACCOUNTS", &p.accounts);
    let dev_seed = std::env::var("KEYSTONE_DEV_SEED").as_deref() == Ok("1");
    if accounts.exists() {
        match AccountFile::load(&accounts) {
            Ok(f) => {
                c.ok(
                    "accounts",
                    format!("{} ({} accounts)", accounts.display(), f.accounts.len()),
                );
                for problem in account_problems(&f) {
                    c.fail("accounts", problem);
                }
            }
            Err(e) => c.fail("accounts", e.to_string()),
        }
    } else if dev_seed && insecure {
        c.warn("accounts", "no accounts file — dev seed accounts only");
    } else {
        c.fail(
            "accounts",
            format!(
                "{} missing — the server has no entitlement backend",
                accounts.display()
            ),
        );
    }

    match load_payload_epoch() {
        Ok(e) => c.ok("KEYSTONE_PAYLOAD_EPOCH", e.to_string()),
        Err(e) => c.fail("KEYSTONE_PAYLOAD_EPOCH", e.to_string()),
    }
    let payload_dir = ws.env_or("KEYSTONE_PAYLOAD_DIR", &p.payload_dir);
    if payload_dir.is_dir() {
        match payload_layout_problems(&payload_dir) {
            Ok((count, problems)) if problems.is_empty() => c.ok(
                "payload layout",
                format!("{} ({count} artifacts)", payload_dir.display()),
            ),
            Ok((_, problems)) => {
                for problem in problems {
                    c.fail("payload layout", problem);
                }
            }
            Err(e) => c.fail("payload layout", format!("{e:#}")),
        }
        let secret = ws.env_or("KEYSTONE_PAYLOAD_SECRET_FILE", &p.payload_secret);
        match read_payload_secret(&secret) {
            Ok(_) => c.ok("payload secret", secret.display().to_string()),
            Err(e) => c.fail("payload secret", format!("{e:#}")),
        }
    } else if std::env::var_os("KEYSTONE_PAYLOAD_DIR").is_some() {
        c.fail(
            "payload layout",
            format!("KEYSTONE_PAYLOAD_DIR {} missing", payload_dir.display()),
        );
    } else {
        c.warn(
            "payload layout",
            format!("{} missing — payloads disabled", payload_dir.display()),
        );
    }

    if c.failures > 0 {
        bail!("{} preflight check(s) failed", c.failures);
    }
    println!("all checks passed");
    Ok(())
}

/// Reuse `{name}-cert.pem` unless `reissue`, else sign a new one; returns the cert sha256.
fn dev_client_cert(ws: &Workspace, name: &str, reissue: bool) -> Result<String> {
    let cert = ws.root.join(format!("{name}-cert.pem"));
    let key = ws.root.join(format!("{name}-key.pem"));
    if !reissue && cert.exists() && key.exists() {
        let der = CertificateDer::from_pem_file(&cert)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", cert.display()))?;
        return Ok(hex::encode(Sha256::digest(&der)));
    }
    issue_client_cert(ws, name, true)
}

/// `dev`: provision CA, server cert, a pinned dev account with a live grant,
/// an admin client cert, and payload material; run the server under mTLS
/// with the admin listener.
fn cmd_dev() -> Result<()> {
    let ws = Workspace::load()?;
    let p = &ws.cfg.paths;
    let keyfile = ws.path(&p.keyfile);
    if !keyfile.exists() {
        println!("no keyfile — generating one");
        cmd_keygen(1, Some(keyfile.clone()), false)?;
    }
    let issuer = read_issuer(&keyfile)?;

    let (ca_cert, ca_key) = ws.ca_paths();
    let fresh_ca = !ca_cert.exists() || !ca_key.exists();
    if fresh_ca {
        println!("no CA — generating one");
        cmd_ca(false)?;
    }
    // A new CA invalidates every certificate the old one signed.
    let cert = ws.path(&p.cert);
    let cert_key = ws.path(&p.cert_key);
    if fresh_ca || !cert.exists() || !cert_key.exists() {
        println!("issuing the server cert");
        cmd_cert(&ws, &[], KeySource::Existing, false)?;
    }
    let admin_cert = dev_client_cert(&ws, ADMIN_CERT_NAME, fresh_ca)?;
    let dev_cert = dev_client_cert(&ws, DEV_ACCOUNT, fresh_ca)?;

    let accounts = ws.path(DEV_ACCOUNTS);
    let mut file = load_accounts(&accounts)?;
    if !file.accounts.iter().any(|a| a.name == DEV_ACCOUNT) {
        file.accounts.push(AccountRecord {
            name: DEV_ACCOUNT.into(),
            secret_hash: hash_secret(DEV_SECRET)?,
            entitlements: vec![],
            cert_sha256: None,
        });
    }
    let record = file
        .accounts
        .iter_mut()
        .find(|a| a.name == DEV_ACCOUNT)
        .expect("inserted above");
    record.cert_sha256 = Some(dev_cert);
    let now = Utc::now();
    if !record
        .entitlements
        .iter()
        .any(|g| g.product == DEV_PRODUCT && g.expires_at > now)
    {
        record.entitlements.retain(|g| g.product != DEV_PRODUCT);
        record.entitlements.push(AccountGrant {
            product: DEV_PRODUCT.into(),
            expires_at: now + chrono::Duration::days(30),
            features: vec![],
        });
    }
    file.save(&accounts)?;

    let payload_secret = ws.path(&p.payload_secret);
    if !payload_secret.exists() {
        println!("no payload secret — generating one");
        cmd_payload_secret(Some(payload_secret.clone()), false)?;
    }
    let payload_dir = ws.path(&p.payload_dir);
    std::fs::create_dir_all(&payload_dir)
        .with_context(|| format!("creating {}", payload_dir.display()))?;

    // Fresh per run and never persisted, so rotation is free.
    let admin_token = random_hex(32);
    let env: Vec<(&str, OsString)> = vec![
        ("KEYSTONE_BIND", "127.0.0.1:8443".into()),
        ("KEYSTONE_ADMIN_BIND", "127.0.0.1:8444".into()),
        ("KEYSTONE_KEYFILE", keyfile.into()),
        ("KEYSTONE_TLS_CERT", cert.into()),
        ("KEYSTONE_TLS_KEY", cert_key.into()),
        ("KEYSTONE_CA_CERT", ca_cert.into()),
        ("KEYSTONE_ADMIN_CERT_SHA256", admin_cert.into()),
        ("KEYSTONE_ACCOUNTS", accounts.into()),
        ("KEYSTONE_PAYLOAD_DIR", payload_dir.into()),
        ("KEYSTONE_PAYLOAD_SECRET_FILE", payload_secret.into()),
        ("KEYSTONE_REVOCATIONS_FILE", ws.path(&p.revocations).into()),
    ];

    println!();
    println!("environment for this server run:");
    for (name, value) in &env {
        println!("  {name}={}", value.to_string_lossy());
    }
    println!("  KEYSTONE_ADMIN_TOKEN={}", admin_token.as_str());
    println!();
    println!(
        "active key id {} (pubkey {})",
        issuer.key_id(),
        pubkey_hex(&issuer)
    );
    println!(
        "dev account {DEV_ACCOUNT}/{DEV_SECRET} (product {DEV_PRODUCT:?}) with {DEV_ACCOUNT}-cert.pem; \
         admin client {ADMIN_CERT_NAME}-cert.pem"
    );
    println!();

    let mut cmd = Command::new("cargo");
    cmd.args(["run", "-p", SERVER_BIN])
        .current_dir(workspace_root())
        .envs(env)
        .env("KEYSTONE_ADMIN_TOKEN", admin_token.as_str())
        .env_remove("KEYSTONE_ALLOW_INSECURE")
        .env_remove("KEYSTONE_DEV_SEED");
    run(&mut cmd)
}

/// `deploy`: release build, then ship the binary, key material, accounts,
/// revocations, and an env file; secrets end up mode 600 on the target.
fn cmd_deploy() -> Result<()> {
    let ws = Workspace::load()?;
    let p = &ws.cfg.paths;
    let target = ws
        .cfg
        .target
        .as_ref()
        .context("xtask.toml needs a [target] section to deploy")?;
    let remote_dir = ws
        .cfg
        .deploy
        .as_ref()
        .context("xtask.toml needs a [deploy] section to deploy")?
        .remote_path
        .trim_end_matches('/');
    let remote = format!("{}@{}", target.username, target.host);

    let keyfile = ws.path(&p.keyfile);
    let issuer = read_issuer(&keyfile)?;
    let accounts = ws.path(&p.accounts);
    AccountFile::load(&accounts)?;
    let payload_secret = ws.path(&p.payload_secret);
    read_payload_secret(&payload_secret)?;
    let admin_token = match std::env::var("KEYSTONE_ADMIN_TOKEN") {
        Ok(token) => {
            let token = Zeroizing::new(token);
            check_admin_token(&token)?;
            token
        }
        Err(_) => random_hex(32),
    };
    let admin_certs = match std::env::var("KEYSTONE_ADMIN_CERT_SHA256") {
        Ok(raw) => parse_admin_cert_hashes(&raw)?,
        Err(_) => {
            let path = ws.root.join(format!("{ADMIN_CERT_NAME}-cert.pem"));
            let der = CertificateDer::from_pem_file(&path).map_err(|e| {
                anyhow::anyhow!(
                    "{}: {e} — set KEYSTONE_ADMIN_CERT_SHA256 or run `cargo xtask issue-cert {ADMIN_CERT_NAME}`",
                    path.display()
                )
            })?;
            BTreeSet::from([hex::encode(Sha256::digest(&der))])
        }
    };
    // (local path, secret)
    let files = [
        (keyfile, true),
        (ws.path(&p.cert), false),
        (ws.path(&p.cert_key), true),
        (ws.path(&p.ca_cert), false),
        (accounts, true),
        (payload_secret, true),
    ];
    for (path, _) in &files {
        ensure!(
            path.is_file(),
            "{} missing — provision it before deploying",
            path.display()
        );
    }
    let remote_file = |path: &Path| -> String {
        let name = path
            .file_name()
            .expect("configured paths name files")
            .to_string_lossy();
        format!("{remote_dir}/{name}")
    };

    // Union with the target's list so a deploy never un-revokes a key.
    let revocations = ws.path(&p.revocations);
    let remote_revocations = remote_file(&revocations);
    let out = Command::new("ssh")
        .arg(&remote)
        .arg(format!(
            "cat {} 2>/dev/null || true",
            sh_quote(&remote_revocations)
        ))
        .output()
        .context("spawning ssh")?;
    ensure!(
        out.status.success(),
        "ssh {remote} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut revoked = load_revocations(&revocations)?;
    revoked.extend(
        revocations::parse(&out.stdout)
            .with_context(|| format!("parsing {remote}:{remote_revocations}"))?,
    );
    revoked.extend(env_revoked_key_ids()?);
    ensure!(
        !revoked.contains(&issuer.key_id()),
        "active key id {} is revoked — generate a new key with `cargo xtask keygen`",
        issuer.key_id()
    );
    write_secret(&revocations, &revocations::serialize(&revoked), true)?;

    let root = workspace_root();
    run(Command::new("cargo")
        .args(["build", "--release", "-p", SERVER_BIN])
        .current_dir(&root))?;
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(|d| root.join(d))
        .unwrap_or_else(|| root.join("target"));
    let binary = target_dir
        .join("release")
        .join(format!("{SERVER_BIN}{}", std::env::consts::EXE_SUFFIX));
    ensure!(
        binary.exists(),
        "expected build artifact {}",
        binary.display()
    );

    let [keyfile, cert, cert_key, ca_cert, accounts, payload_secret] =
        files.each_ref().map(|(path, _)| remote_file(path));
    let env = Zeroizing::new(format!(
        "KEYSTONE_BIND=0.0.0.0:8443\n\
         KEYSTONE_ADMIN_BIND=127.0.0.1:8444\n\
         KEYSTONE_KEYFILE={keyfile}\n\
         KEYSTONE_TLS_CERT={cert}\n\
         KEYSTONE_TLS_KEY={cert_key}\n\
         KEYSTONE_CA_CERT={ca_cert}\n\
         KEYSTONE_ACCOUNTS={accounts}\n\
         KEYSTONE_PAYLOAD_DIR={remote_dir}/payloads\n\
         KEYSTONE_PAYLOAD_SECRET_FILE={payload_secret}\n\
         KEYSTONE_PAYLOAD_EPOCH={epoch}\n\
         KEYSTONE_REVOCATIONS_FILE={remote_revocations}\n\
         KEYSTONE_ADMIN_CERT_SHA256={admin_certs}\n\
         KEYSTONE_ADMIN_TOKEN={token}\n",
        epoch = load_payload_epoch()?,
        admin_certs = admin_certs.into_iter().collect::<Vec<_>>().join(","),
        token = admin_token.as_str(),
    ));
    let env_file = std::env::temp_dir().join(format!("keystone-{}.env", random_hex(8).as_str()));
    write_secret(&env_file, env.as_bytes(), false)?;
    let shipped = ship(
        &remote,
        remote_dir,
        &binary,
        &files,
        &revocations,
        &env_file,
    );
    let _ = std::fs::remove_file(&env_file);
    shipped?;

    println!("deployed to {remote}:{remote_dir}/");
    println!(
        "  active key id {} (pubkey {})",
        issuer.key_id(),
        pubkey_hex(&issuer)
    );
    println!("  run: set -a; . {remote_dir}/{ENV_FILE}; set +a; {remote_dir}/{SERVER_BIN}");
    println!("  admin token: KEYSTONE_ADMIN_TOKEN in {remote_dir}/{ENV_FILE}");
    Ok(())
}

/// Copy everything to the target; secrets are pre-created and re-chmodded 600.
fn ship(
    remote: &str,
    remote_dir: &str,
    binary: &Path,
    files: &[(PathBuf, bool)],
    revocations: &Path,
    env_file: &Path,
) -> Result<()> {
    let name = |path: &Path| -> String {
        sh_quote(
            &path
                .file_name()
                .expect("shipped paths name files")
                .to_string_lossy(),
        )
    };
    let mut secrets: Vec<String> = files
        .iter()
        .filter(|(_, secret)| *secret)
        .map(|(path, _)| name(path))
        .collect();
    secrets.push(name(revocations));
    secrets.push(sh_quote(ENV_FILE));
    let secrets = secrets.join(" ");
    let dir = sh_quote(remote_dir);

    // Pre-create secrets owner-only so no copy is ever world-readable.
    run(Command::new("ssh").arg(remote).arg(format!(
        "mkdir -p {dir} {dir}/payloads && cd {dir} && umask 077 && touch {secrets} && chmod 600 {secrets}"
    )))?;
    let mut scp = Command::new("scp");
    scp.arg(binary);
    for (path, _) in files {
        scp.arg(path);
    }
    run(scp.arg(revocations).arg(format!("{remote}:{remote_dir}/")))?;
    run(Command::new("scp")
        .arg(env_file)
        .arg(format!("{remote}:{remote_dir}/{ENV_FILE}")))?;
    run(Command::new("ssh").arg(remote).arg(format!(
        "cd {dir} && chmod 600 {secrets} && chmod 755 {}",
        sh_quote(SERVER_BIN)
    )))
}

/// `--file`, then `KEYSTONE_ACCOUNTS`, then the configured accounts path.
fn accounts_path(args: &[String], ws: Option<&Workspace>) -> Result<PathBuf> {
    if let Some(p) = take_value(args, "--file")? {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = std::env::var_os("KEYSTONE_ACCOUNTS") {
        return Ok(PathBuf::from(p));
    }
    Ok(match ws {
        Some(ws) => ws.path(&ws.cfg.paths.accounts),
        None => {
            let ws = Workspace::load()?;
            ws.path(&ws.cfg.paths.accounts)
        }
    })
}

/// Missing file = empty table; a malformed file is an error, never overwritten.
fn load_accounts(path: &Path) -> Result<AccountFile> {
    if !path.exists() {
        return Ok(AccountFile::default());
    }
    AccountFile::load(path)
        .map_err(|e| anyhow::anyhow!("{e} — fix or remove it; refusing to clobber"))
}

/// Records the wire protocol would reject: bad account names or grant products.
fn account_problems(file: &AccountFile) -> Vec<String> {
    let mut problems = Vec::new();
    for account in &file.accounts {
        if let Err(e) = check_account_name(&account.name) {
            problems.push(e.to_string());
        }
        for grant in &account.entitlements {
            if let Err(e) = check_product(&grant.product) {
                problems.push(format!("account {:?}: {e}", account.name));
            }
        }
    }
    problems
}

fn hash_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing secret: {e}"))?
        .to_string())
}

/// First argument, which must be positional.
fn positional(args: &[String], usage: &str) -> Result<String> {
    match args.first() {
        Some(name) if !name.starts_with("--") => Ok(name.clone()),
        _ => bail!("{usage}"),
    }
}

fn account_name(args: &[String], sub: &str) -> Result<String> {
    positional(
        args,
        &format!("usage: cargo xtask account {sub} <name> [flags]"),
    )
}

/// `account add <name> [--secret s]`: argon2-hash a new account's secret.
/// Without `--secret` the secret is prompted for (argv leaks via ps and history).
fn account_add(args: &[String]) -> Result<()> {
    let name = account_name(args, "add")?;
    check_account_name(&name)?;
    let secret = match take_value(args, "--secret")? {
        Some(s) => {
            eprintln!("warning: --secret leaks via argv (ps, shell history) — prefer the prompt");
            Zeroizing::new(s)
        }
        None => prompt_secret(&name)?,
    };
    ensure!(!secret.is_empty(), "account secret must not be empty");
    let path = accounts_path(args, None)?;
    let mut file = load_accounts(&path)?;
    ensure!(
        !file.accounts.iter().any(|a| a.name == name),
        "account {name} already exists in {}",
        path.display()
    );
    file.accounts.push(AccountRecord {
        name: name.clone(),
        secret_hash: hash_secret(&secret)?,
        entitlements: vec![],
        cert_sha256: None,
    });
    file.save(&path)?;
    println!("added account {name} to {}", path.display());
    Ok(())
}

/// Terminal: echo off, asked twice. Piped stdin: read verbatim.
fn prompt_secret(name: &str) -> Result<Zeroizing<String>> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .read_line(&mut line)
            .context("reading account secret from stdin")?;
        return Ok(Zeroizing::new(
            line.trim_end_matches(['\r', '\n']).to_string(),
        ));
    }
    let first = Zeroizing::new(
        rpassword::prompt_password(format!("secret for {name}: "))
            .context("reading account secret")?,
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("confirm secret: ").context("reading account secret")?,
    );
    ensure!(first == second, "secrets did not match");
    Ok(first)
}

/// `account grant <name> --product p --days n [--features a,b]`: re-granting replaces.
fn account_grant(args: &[String]) -> Result<()> {
    let name = account_name(args, "grant")?;
    let product = take_value(args, "--product")?.context("account grant requires --product <p>")?;
    check_product(&product)?;
    let days: i64 = take_value(args, "--days")?
        .context("account grant requires --days <n>")?
        .parse()
        .context("--days must be an integer")?;
    // A non-positive grant is born expired.
    ensure!(days > 0, "--days must be positive, got {days}");
    let features = take_value(args, "--features")?
        .map(|f| {
            f.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let path = accounts_path(args, None)?;
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
    file.save(&path)?;
    println!("granted {name} {product} until {}", expires_at.to_rfc3339());
    Ok(())
}

/// `account revoke <name> --product p`: fails when no such grant exists.
fn account_revoke(args: &[String]) -> Result<()> {
    let name = account_name(args, "revoke")?;
    let product =
        take_value(args, "--product")?.context("account revoke requires --product <p>")?;
    let path = accounts_path(args, None)?;
    let mut file = load_accounts(&path)?;
    let record = file
        .accounts
        .iter_mut()
        .find(|a| a.name == name)
        .with_context(|| format!("no account {name} in {}", path.display()))?;
    let before = record.entitlements.len();
    record.entitlements.retain(|g| g.product != product);
    ensure!(
        record.entitlements.len() < before,
        "account {name} holds no grant for {product}"
    );
    file.save(&path)?;
    println!("revoked {name}'s grant for {product}");
    Ok(())
}

/// `account list`: names, grants, cert binding; never secret hashes.
fn account_list(args: &[String]) -> Result<()> {
    let path = accounts_path(args, None)?;
    let file = load_accounts(&path)?;
    if file.accounts.is_empty() {
        println!("no accounts in {}", path.display());
        return Ok(());
    }
    let now = Utc::now();
    for a in &file.accounts {
        let cert = if a.cert_sha256.is_some() {
            "cert-bound"
        } else {
            "any CA cert"
        };
        println!("{} ({cert})", a.name);
        for g in &a.entitlements {
            let state = if g.expires_at > now {
                "expires"
            } else {
                "EXPIRED"
            };
            println!(
                "  {} — {state} {}  features: {}",
                g.product,
                g.expires_at.to_rfc3339(),
                g.features.join(",")
            );
        }
    }
    Ok(())
}

fn cmd_account(args: &[String]) -> Result<()> {
    let Some(sub) = args.first() else {
        bail!("usage: cargo xtask account <add|grant|revoke|list> ...");
    };
    let rest = &args[1..];
    match sub.as_str() {
        "add" => account_add(rest),
        "grant" => account_grant(rest),
        "revoke" => account_revoke(rest),
        "list" => account_list(rest),
        _ => bail!("unknown account subcommand {sub}"),
    }
}

fn usage() -> ! {
    eprintln!(
        "cargo xtask <command>

  keygen --key-id <n> [--out <path>] [--force]
        write a {KEYFILE_LEN}-byte keyfile (default keystone-<n>.key); print key id + pubkey
  ca [--force]
        generate the keystone CA (signs server + client certs)
  cert [--host <name>]... [--key <pem> | --new-key] [--force]
        server TLS cert (SANs localhost, 127.0.0.1, each --host); reuses the
        server key unless told otherwise; prints the SPKI sha256 clients pin
  spki <pem>
        print the SPKI sha256 of a certificate or private key
  tls-key --out <path> [--force]
        pre-generate the next server key; prints its SPKI sha256 so clients
        can pin it before `cert --key <path> --force` swaps it in
  issue-cert <account> [--file <accounts>] [--force]
        client cert (CN=<account>); pins it on the account when present;
        `issue-cert {ADMIN_CERT_NAME}` mints the admin client for
        KEYSTONE_ADMIN_CERT_SHA256
  payload-secret [--out <path>] [--force]
        mint the 32-byte artifact sealing secret
  seal --product <p> --version <v> --in <file> [--out <dir>] [--build-id <id>]
        seal into <dir>/<p>/<v>.bin with .sha256 and .build sidecars
  verify
        preflight checklist against the server environment
  dev
        provision CA, server cert, a pinned dev account ({DEV_ACCOUNTS}), an
        admin client cert, and payload material; run the server under mTLS
        with the admin listener
  deploy
        release build; ship binary, key material, accounts, revocations, and an
        env file (admin cert hashes from KEYSTONE_ADMIN_CERT_SHA256 or
        {ADMIN_CERT_NAME}-cert.pem)
  account <add|grant|revoke|list> <name> [--file <path>]
        manage the accounts file

XTASK_ROOT overrides the directory holding xtask.toml and config-relative paths."
    );
    exit(2);
}

/// Value of the first `flag value` pair, or None.
fn take_value(args: &[String], flag: &str) -> Result<Option<String>> {
    Ok(take_values(args, flag)?.into_iter().next())
}

/// Values of every `flag value` pair, in order.
fn take_values(args: &[String], flag: &str) -> Result<Vec<String>> {
    let mut values = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            values.push(
                iter.next()
                    .with_context(|| format!("{flag} requires a value"))?
                    .clone(),
            );
        }
    }
    Ok(values)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        usage();
    };
    let rest = &args[1..];
    let force = rest.iter().any(|a| a == "--force");
    let has = |flag: &str| rest.iter().any(|a| a == flag);

    match cmd.as_str() {
        "keygen" => cmd_keygen(
            parse_key_id(take_value(rest, "--key-id")?)?,
            take_value(rest, "--out")?.map(PathBuf::from),
            force,
        ),
        "ca" => cmd_ca(force),
        "cert" => {
            let source = match (take_value(rest, "--key")?, has("--new-key")) {
                (Some(_), true) => bail!("--key and --new-key are mutually exclusive"),
                (Some(path), false) => KeySource::File(path.into()),
                (None, true) => KeySource::New,
                (None, false) => KeySource::Existing,
            };
            cmd_cert(
                &Workspace::load()?,
                &take_values(rest, "--host")?,
                source,
                force,
            )
        }
        "spki" => cmd_spki(rest.first()),
        "tls-key" => cmd_tls_key(take_value(rest, "--out")?.map(PathBuf::from), force),
        "issue-cert" => cmd_issue_cert(rest, force),
        "payload-secret" => {
            cmd_payload_secret(take_value(rest, "--out")?.map(PathBuf::from), force)
        }
        "seal" => cmd_seal(SealArgs {
            product: take_value(rest, "--product")?,
            version: take_value(rest, "--version")?,
            input: take_value(rest, "--in")?,
            out_dir: take_value(rest, "--out")?.map(PathBuf::from),
            build_id: take_value(rest, "--build-id")?,
        }),
        "verify" => cmd_verify(),
        "dev" => cmd_dev(),
        "deploy" => cmd_deploy(),
        "account" => cmd_account(rest),
        _ => usage(),
    }
}
