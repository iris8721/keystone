//! PoC: per-download artifact mutation against a live keystone.
//!
//! `upload <dll>` publishes a plaintext artifact over the admin listener.
//! `prove <out1> <out2>` runs TWO independent licensed flows — exchange →
//! handoff → attest → payload fetch → download — and shows the two
//! downloads verify against their signed manifests yet differ from each
//! other, proving the server mutated each download independently.
//!
//! Environment (paths/hashes only; secrets come from the environment):
//!   POC_URL, POC_ACCOUNT, POC_SECRET, POC_PRODUCT, POC_VERSION,
//!   POC_CERT, POC_KEY, POC_SPKI (64 hex chars), POC_KEYFILE,
//!   POC_ADMIN_URL, POC_ADMIN_TOKEN, POC_ADMIN_CERT, POC_ADMIN_KEY.

use std::time::Duration;

use keystone_client::{
    AdminClient, ClientIdentity, DEFAULT_HANDOFF_TTL, KeystoneClient, PendingSession,
    TrustedIssuers,
};
use keystone_core::{Issuer, Manifest};
use rand::RngCore;
use sha2::{Digest, Sha256};

const PROCESS_ID: &str = "poc-app.exe";

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

fn pin() -> [u8; 32] {
    let text = env("POC_SPKI");
    let mut pin = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut pin)
        .unwrap_or_else(|e| panic!("POC_SPKI must be 64 hex chars: {e}"));
    pin
}

fn issuers() -> TrustedIssuers {
    let keyfile = read(&env("POC_KEYFILE"));
    let issuer = Issuer::from_keyfile(&keyfile).expect("keyfile");
    TrustedIssuers::single(issuer.key_id(), issuer.verifying_key())
}

async fn upload(dll: &str) {
    let admin = AdminClient::builder(env("POC_ADMIN_URL"))
        .pin_spki(pin())
        .identity(ClientIdentity::from_pem(
            read(&env("POC_ADMIN_CERT")),
            read(&env("POC_ADMIN_KEY")),
        ))
        .admin_token(env("POC_ADMIN_TOKEN"))
        .build()
        .expect("admin client config");
    let product = env("POC_PRODUCT");
    let version = env("POC_VERSION");
    let bytes = read(dll);
    let sha = hex::encode(Sha256::digest(&bytes));
    let published = admin
        .publish_artifact(&product, &version, "poc-build-1", bytes)
        .await
        .expect("publish");
    println!("uploaded {dll} ({product} {version})");
    println!("  plaintext sha256: {sha}");
    println!(
        "  server acked sha256: {} build {} product {}/{}",
        published.sha256, published.build_id, published.product, published.version
    );
}

fn describe(manifest: &Manifest) -> String {
    format!(
        "sha256 {} build {} product {} version {}",
        hex32(&manifest.sha256),
        manifest.build_id,
        manifest.product,
        manifest.version
    )
}

/// One licensed client from scratch: its own transport, credentials,
/// hardware id, and session. Returns (manifest sha256, downloaded sha256).
async fn licensed_flow(label: &str, out: &str) -> ([u8; 32], [u8; 32]) {
    let account = env("POC_ACCOUNT");
    let product = env("POC_PRODUCT");
    let version = env("POC_VERSION");
    let client = KeystoneClient::builder(env("POC_URL"), issuers())
        .pin_spki(pin())
        .identity(ClientIdentity::from_pem(
            read(&env("POC_CERT")),
            read(&env("POC_KEY")),
        ))
        .download_timeout(Duration::from_secs(300))
        .timeout(Duration::from_secs(60))
        .build()
        .expect("client config");

    let mut hwid = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut hwid);

    // Loader session.
    let loader = client
        .exchange(&account, &env("POC_SECRET"), &product, hwid)
        .await
        .expect("exchange");
    println!("[{label}] exchange ok: session {}", loader.session_id());

    // Handoff to the protected application, then attest as the child.
    let token = client
        .create_handoff(&loader, PROCESS_ID, DEFAULT_HANDOFF_TTL)
        .await
        .expect("handoff");
    let pending = PendingSession::from_handoff(token, PROCESS_ID).expect("handoff token");
    let app = client.attest(pending).await.expect("attest");
    println!(
        "[{label}] attest ok: session {} (child of {})",
        app.session_id(),
        loader.session_id()
    );

    // Payload fetch: the signed manifest for this exact download.
    let (manifest, _artifact_key) = client
        .fetch_manifest(&app, &product, &version)
        .await
        .expect("payload fetch");
    println!(
        "[{label}] payload fetch ok: manifest {}",
        describe(&manifest.manifest)
    );

    // Download, decrypt, and verify against the signed manifest
    // (download_payload refuses bytes whose sha256 differs from the manifest).
    let payload = client
        .download_payload(&app, &product, &version)
        .await
        .expect("download");
    std::fs::write(out, &payload.bytes).expect("writing download");
    let on_disk = Sha256::digest(std::fs::read(out).expect("re-reading download"));
    let manifest_sha = payload.manifest.manifest.sha256;
    assert_eq!(
        on_disk.as_slice(),
        manifest_sha.as_slice(),
        "downloaded file must hash to the signed manifest sha256"
    );
    println!("[{label}] download ok -> {out}");
    println!("[{label}] manifest sha256 : {}", hex32(&manifest_sha));
    println!("[{label}] file sha256     : {}", hex32(&on_disk.into()));
    (manifest_sha, on_disk.into())
}

async fn prove(out1: &str, out2: &str) {
    let (m1, d1) = licensed_flow("run1", out1).await;
    let (m2, d2) = licensed_flow("run2", out2).await;
    println!();
    println!("run1 manifest==file: {}", m1 == d1);
    println!("run2 manifest==file: {}", m2 == d2);
    println!("run1 sha256: {}", hex32(&d1));
    println!("run2 sha256: {}", hex32(&d2));
    assert_ne!(d1, d2, "two downloads must differ (per-download mutation)");
    println!("PER-DOWNLOAD MUTATION: PROVEN (downloads differ, each matches its signed manifest)");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("upload") => upload(args.get(1).expect("usage: poc_download upload <dll>")).await,
        Some("prove") => {
            prove(
                args.get(1)
                    .expect("usage: poc_download prove <out1> <out2>"),
                args.get(2)
                    .expect("usage: poc_download prove <out1> <out2>"),
            )
            .await
        }
        _ => {
            eprintln!("usage: poc_download <upload <dll> | prove <out1> <out2>>");
            std::process::exit(2);
        }
    }
}
