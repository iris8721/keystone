//! Live end-to-end probe of fuzzy machine binding against a running
//! keystone (the home cluster's public listener). Not part of the test
//! suite; run manually:
//!
//! ```text
//! E2E_ACCOUNT=.. E2E_SECRET=.. cargo run --example e2e_fuzzy -- \
//!     https://192.168.0.85:8443 <ca.pem> <keystone-1.key> lumen-cli
//! ```
use keystone_client::{ClientError, ClientIdentity, HwidComponent, HwidComponentKind, KeystoneClient, TrustedIssuers};
use keystone_core::wire::ErrorCode;
use keystone_core::Issuer;

/// One machine persona: six component hashes (any stable 32 bytes; the
/// server never sees raw serials) plus an anomaly-telemetry hwid.
struct Machine {
    smbios: [u8; 32],
    board: [u8; 32],
    disk: [u8; 32],
    guid: [u8; 32],
    macs: Vec<[u8; 32]>,
    cpu: [u8; 32],
    hwid: [u8; 32],
}

fn filled(byte: u8) -> [u8; 32] {
    [byte; 32]
}

impl Machine {
    fn a() -> Self {
        Machine { smbios: filled(1), board: filled(2), disk: filled(3), guid: filled(4), macs: vec![filled(5)], cpu: filled(6), hwid: filled(0xA1) }
    }
    /// Machine A after a USB NIC change: only the MAC differs (low weight).
    fn a_new_nic() -> Self {
        let mut m = Self::a();
        m.macs = vec![filled(7)];
        m
    }
    /// A different machine: new motherboard (both chassis kinds) and disk.
    fn b() -> Self {
        Machine { smbios: filled(8), board: filled(9), disk: filled(10), guid: filled(11), macs: vec![filled(12)], cpu: filled(13), hwid: filled(0xB1) }
    }
    /// Machine C, unknown to the server until the lock clears.
    fn c() -> Self {
        Machine { smbios: filled(14), board: filled(15), disk: filled(16), guid: filled(17), macs: vec![filled(18)], cpu: filled(19), hwid: filled(0xC1) }
    }

    fn components(&self) -> Vec<HwidComponent> {
        let mut v = vec![
            HwidComponent { kind: HwidComponentKind::SmbiosUuid, hash: self.smbios },
            HwidComponent { kind: HwidComponentKind::BoardSerial, hash: self.board },
            HwidComponent { kind: HwidComponentKind::DiskSerial, hash: self.disk },
            HwidComponent { kind: HwidComponentKind::MachineGuid, hash: self.guid },
            HwidComponent { kind: HwidComponentKind::CpuName, hash: self.cpu },
        ];
        for mac in &self.macs {
            v.push(HwidComponent { kind: HwidComponentKind::MacAddress, hash: *mac });
        }
        v
    }
}

fn verdict(name: &str, ok: bool) -> bool {
    println!("{} {}", if ok { "PASS" } else { "FAIL" }, name);
    ok
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let base = args.next().expect("base url");
    let ca_path = args.next().expect("ca pem path");
    let keyfile_path = args.next().expect("issuer keyfile path");
    let product = args.next().expect("product");
    let account = std::env::var("E2E_ACCOUNT").expect("E2E_ACCOUNT");
    let secret = std::env::var("E2E_SECRET").expect("E2E_SECRET");
    let rebind = std::env::var("E2E_REBIND").is_ok();

    let issuer = Issuer::from_keyfile(&std::fs::read(&keyfile_path).expect("keyfile")).unwrap();
    let issuers = TrustedIssuers::from_public_keys([(issuer.key_id(), issuer.verifying_key().to_bytes())]).unwrap();
    let mut builder = KeystoneClient::builder(base, issuers).server_ca_pem(std::fs::read(&ca_path).unwrap());
    if let (Ok(cert), Ok(key)) = (std::env::var("E2E_CLIENT_CERT"), std::env::var("E2E_CLIENT_KEY")) {
        builder = builder.identity(ClientIdentity::from_pem(std::fs::read(cert).unwrap(), std::fs::read(key).unwrap()));
    }
    let client: KeystoneClient = builder.build().unwrap();

    let mut all_ok = true;

    if rebind {
        // After the operator cleared the lock: a new machine must bind.
        all_ok &= verdict("rebind: machine C first exchange binds", client.exchange_components(&account, &secret, &product, Machine::c().hwid, Machine::c().components()).await.is_ok());
        return;
    }

    // 1. First exchange from machine A binds the component set.
    all_ok &= verdict("bind: machine A first exchange", client.exchange_components(&account, &secret, &product, Machine::a().hwid, Machine::a().components()).await.is_ok());

    // 2. Same machine again: accepted.
    all_ok &= verdict("same machine: accepted", client.exchange_components(&account, &secret, &product, Machine::a().hwid, Machine::a().components()).await.is_ok());

    // 3. NIC change (weight 1 of 14): accepted with self-heal.
    all_ok &= verdict("upgrade: new NIC accepted + healed", client.exchange_components(&account, &secret, &product, Machine::a_new_nic().hwid, Machine::a_new_nic().components()).await.is_ok());

    // 4. Different motherboard (weights 4+4): rejected.
    match client.exchange_components(&account, &secret, &product, Machine::b().hwid, Machine::b().components()).await {
        Err(ClientError::ServerRejected { code: Some(ErrorCode::HwidMismatch), .. }) => { verdict("chassis swap: rejected hwid_mismatch", true); }
        other => { println!("FAIL chassis swap: expected hwid_mismatch, got {:?}", other.err()); all_ok = false; }
    }

    // 5. Protocol-flavor guard: a legacy single-hash request on a component-bound account is rejected.
    match client.exchange(&account, &secret, &product, Machine::b().hwid).await {
        Err(ClientError::ServerRejected { code: Some(ErrorCode::HwidMismatch), .. }) => { verdict("flavor guard: legacy request rejected", true); }
        other => { println!("FAIL flavor guard: expected hwid_mismatch, got {:?}", other.err()); all_ok = false; }
    }

    std::process::exit(if all_ok { 0 } else { 1 });
}
