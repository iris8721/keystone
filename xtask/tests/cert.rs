//! `xtask cert` / `tls-key` / `spki` / `issue-cert`: SANs, a server key
//! (and so the client SPKI pin) that survives re-issue, and account pins.

mod common;

use common::{cert_der, ok, run, sha256_hex, stdout, workdir};
use rcgen::SanType;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

fn sans(cert: &Path) -> Vec<SanType> {
    let pem = std::fs::read_to_string(cert).unwrap();
    rcgen::CertificateParams::from_ca_cert_pem(&pem)
        .unwrap()
        .subject_alt_names
}

fn dns(name: &str) -> SanType {
    SanType::DnsName(name.try_into().unwrap())
}

/// The pin as `xtask spki` reports it.
fn spki(root: &Path, pem: &Path) -> String {
    stdout(&ok(run(root, &["spki", pem.to_str().unwrap()])))
        .trim()
        .to_string()
}

/// SPKI sha256 of a certificate, computed without xtask.
fn cert_spki(cert: &Path) -> String {
    let der = cert_der(cert);
    let der = rustls_pki_types::CertificateDer::from(der);
    let ee = webpki::EndEntityCert::try_from(&der).unwrap();
    sha256_hex(&ee.subject_public_key_info())
}

#[test]
fn cert_covers_every_host_and_reuses_the_server_key() {
    let root = workdir("cert");
    let cert = root.join("keystone-cert.pem");
    let key = root.join("keystone-key.pem");

    ok(run(
        &root,
        &["cert", "--host", "a.example", "--host", "b.example"],
    ));
    let pin = cert_spki(&cert);
    assert_eq!(spki(&root, &cert), pin);
    assert_eq!(spki(&root, &key), pin);
    let names = sans(&cert);
    for want in [
        dns("localhost"),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dns("a.example"),
        dns("b.example"),
    ] {
        assert!(names.contains(&want), "{want:?} missing from {names:?}");
    }
    let key_pem = std::fs::read(&key).unwrap();

    // Re-issue for another host: new cert, same key, same pin.
    ok(run(&root, &["cert", "--host", "c.example"]));
    assert_eq!(spki(&root, &cert), pin);
    assert_eq!(std::fs::read(&key).unwrap(), key_pem);
    let names = sans(&cert);
    assert!(names.contains(&dns("c.example")));
    assert!(!names.contains(&dns("a.example")));
}

#[test]
fn cert_new_key_requires_force() {
    let root = workdir("cert");
    let cert = root.join("keystone-cert.pem");
    let key = root.join("keystone-key.pem");
    ok(run(&root, &["cert"]));
    let pin = spki(&root, &cert);
    let key_pem = std::fs::read(&key).unwrap();

    let out = run(&root, &["cert", "--new-key"]);
    assert!(!out.status.success(), "replacing the key without --force");
    assert_eq!(std::fs::read(&key).unwrap(), key_pem);

    ok(run(&root, &["cert", "--new-key", "--force"]));
    assert_ne!(spki(&root, &cert), pin);
    assert_ne!(std::fs::read(&key).unwrap(), key_pem);
}

#[test]
fn cert_with_key_file_signs_that_key() {
    let root = workdir("cert");
    let supplied = rcgen::KeyPair::generate().unwrap();
    let path = root.join("supplied.pem");
    std::fs::write(&path, supplied.serialize_pem()).unwrap();

    ok(run(&root, &["cert", "--key", path.to_str().unwrap()]));
    let expected = sha256_hex(&supplied.public_key_der());
    assert_eq!(cert_spki(&root.join("keystone-cert.pem")), expected);
    assert_eq!(spki(&root, &path), expected);
    assert_eq!(
        std::fs::read_to_string(root.join("keystone-key.pem")).unwrap(),
        supplied.serialize_pem()
    );
}

/// Key rotation: the pin of the pre-generated key is the pin the swapped-in cert serves.
#[test]
fn tls_key_pin_matches_cert_after_swap() {
    let root = workdir("cert");
    let cert = root.join("keystone-cert.pem");
    ok(run(&root, &["cert"]));
    let current = spki(&root, &cert);
    let next_path = root.join("next-key.pem");
    let next_arg = next_path.to_str().unwrap();

    let out = ok(run(&root, &["tls-key", "--out", next_arg]));
    let next = spki(&root, &next_path);
    assert!(stdout(&out).contains(&next), "tls-key must print the pin");
    assert_ne!(next, current);
    let before = std::fs::read(&next_path).unwrap();
    assert!(!run(&root, &["tls-key", "--out", next_arg]).status.success());
    assert_eq!(std::fs::read(&next_path).unwrap(), before);

    ok(run(&root, &["cert", "--key", next_arg, "--force"]));
    assert_eq!(cert_spki(&cert), next);
}

#[test]
fn issue_cert_pins_an_existing_account() {
    let root = workdir("issue");
    ok(run(&root, &["ca"]));
    ok(run(
        &root,
        &["account", "add", "alice", "--secret", "s3cret"],
    ));

    let out = ok(run(&root, &["issue-cert", "alice"]));
    let hash = sha256_hex(&cert_der(&root.join("alice-cert.pem")));
    assert!(stdout(&out).contains(&hash), "hash not printed: {out:?}");
    let file = keystone_core::AccountFile::load(&root.join("accounts.json")).unwrap();
    let alice = file.accounts.iter().find(|a| a.name == "alice").unwrap();
    assert_eq!(alice.cert_sha256.as_deref(), Some(hash.as_str()));
}

#[test]
fn issue_cert_for_unknown_account_prints_hash_and_leaves_file_alone() {
    let root = workdir("issue");
    ok(run(&root, &["ca"]));
    ok(run(
        &root,
        &["account", "add", "alice", "--secret", "s3cret"],
    ));
    let before = std::fs::read(root.join("accounts.json")).unwrap();

    let out = ok(run(&root, &["issue-cert", "bob"]));
    let hash = sha256_hex(&cert_der(&root.join("bob-cert.pem")));
    assert!(stdout(&out).contains(&hash), "hash not printed: {out:?}");
    assert_eq!(std::fs::read(root.join("accounts.json")).unwrap(), before);
}

#[test]
fn issue_cert_without_ca_writes_nothing() {
    let root = workdir("issue");
    ok(run(
        &root,
        &["account", "add", "alice", "--secret", "s3cret"],
    ));
    let before = std::fs::read(root.join("accounts.json")).unwrap();
    let out = run(&root, &["issue-cert", "alice"]);
    assert!(!out.status.success(), "issuing without a CA must fail");
    assert!(!root.join("alice-cert.pem").exists());
    assert_eq!(std::fs::read(root.join("accounts.json")).unwrap(), before);
}
