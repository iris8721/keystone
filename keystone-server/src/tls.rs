//! mTLS plumbing: a rustls `ServerConfig` that can demand client
//! certificates, and an axum-server acceptor that surfaces the peer's
//! certificate chain to handlers.
//!
//! axum-server's `RustlsAcceptor` performs the handshake but discards
//! the result — nothing reaches request extensions. `PeerCertAcceptor`
//! wraps it: after the handshake completes it pulls the peer chain off
//! the `TlsStream` and wraps the connection's service so every request
//! on that connection carries a [`PeerCertificates`] extension.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tower_service::Service;

/// The peer's certificate chain (leaf first), inserted into request
/// extensions by [`PeerCertAcceptor`]. Absent entirely when the
/// connection presented no client certificate — which, with
/// `WebPkiClientVerifier` installed, can only happen if TLS client
/// auth was not required.
#[derive(Clone, Debug)]
pub struct PeerCertificates(pub Arc<Vec<CertificateDer<'static>>>);

/// sha256 of the leaf certificate's DER — the value the account file's
/// `cert_sha256` field pins against.
pub fn peer_cert_sha256(peers: &PeerCertificates) -> Option<[u8; 32]> {
    peers.0.first().map(|leaf| Sha256::digest(leaf.as_ref()).into())
}

/// Compare a presented cert hash against the account's pinned hash in
/// constant time — the pin is not secret, but the comparison should
/// not become a timing oracle for partial matches.
pub fn cert_hash_matches(presented: &[u8; 32], pinned: &[u8; 32]) -> bool {
    presented.ct_eq(pinned).into()
}

/// Build the server's TLS config from PEM files.
///
/// `ca_cert_pem` — when `Some`, client certificates are REQUIRED and
/// verified against this CA root (mTLS). When `None`, no client auth
/// is requested — dev mode only.
pub fn load_rustls_config(
    cert_pem: &[u8],
    key_pem: &[u8],
    ca_cert_pem: Option<&[u8]>,
) -> io::Result<RustlsConfig> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificates in server cert PEM",
        ));
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "no private key in server key PEM")
        })?;


    // Explicit provider: the workspace enables both ring and
    // aws-lc-rs on rustls (via reqwest and axum-server), so the
    // crate-feature default is ambiguous and `builder()` would panic.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let builder = match ca_cert_pem {
        Some(ca_pem) => {
            let mut roots = RootCertStore::empty();
            let ca_certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut &ca_pem[..])
                    .collect::<Result<_, _>>()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if ca_certs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "no certificates in CA cert PEM",
                ));
            }
            for ca in ca_certs {
                roots.add(ca).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("bad CA cert: {e}"))
                })?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider,
            )
            .build()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("client cert verifier: {e}"),
                )
            })?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    let mut config = builder
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    // axum-server does not set ALPN itself; without it hyper falls back
    // to http/1.1 anyway, but declaring it keeps h2-capable clients
    // honest about what this server speaks.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

/// An [`Accept`] that runs the rustls handshake via [`RustlsAcceptor`],
/// then attaches the peer certificate chain to every request the
/// connection's service sees.
#[derive(Clone)]
pub struct PeerCertAcceptor {
    inner: RustlsAcceptor,
}

impl PeerCertAcceptor {
    pub fn new(config: RustlsConfig) -> Self {
        Self {
            inner: RustlsAcceptor::new(config),
        }
    }
}

impl<S> Accept<TcpStream, S> for PeerCertAcceptor
where
    S: Send + 'static,
    <RustlsAcceptor as Accept<TcpStream, S>>::Future: Send,
{
    type Stream = TlsStream<TcpStream>;
    type Service = PeerCertService<S>;
    type Future =
        Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let future = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = future.await?;
            // The handshake already ran inside the acceptor; the peer
            // chain is a property of the connection, so it is captured
            // once here rather than per request.
            let peers = stream
                .get_ref()
                .1
                .peer_certificates()
                .map(|certs| certs.to_vec())
                .unwrap_or_default();
            Ok((
                stream,
                PeerCertService {
                    inner: service,
                    peers: PeerCertificates(Arc::new(peers)),
                },
            ))
        })
    }
}

/// Per-connection service wrapper: stamps the peer cert chain onto
/// each request's extensions so handlers can bind accounts to the
/// certificate that carried them.
#[derive(Clone)]
pub struct PeerCertService<S> {
    inner: S,
    peers: PeerCertificates,
}

impl<S, B> Service<axum::http::Request<B>> for PeerCertService<S>
where
    S: Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.peers.clone());
        self.inner.call(req)
    }
}

/// Extract the Common Name from a DER-encoded X.501 Name (the cert's
/// `subject` field). Returns `None` when no CN RDN is present or the
/// value isn't a decodable string.
///
/// Hand-rolled DER walk: pulling in a full X.509 parser just to read
/// one attribute is not worth the dependency. Only the tags rcgen and
/// real CAs actually emit for CN values are decoded.
pub fn subject_common_name(subject_der: &[u8]) -> Option<String> {
    /// One DER TLV: returns (tag, content, rest).
    fn tlv(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, rest) = der.split_first()?;
        let (&len_byte, rest) = rest.split_first()?;
        let (len, rest) = if len_byte & 0x80 == 0 {
            (len_byte as usize, rest)
        } else {
            let n = (len_byte & 0x7f) as usize;
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let mut len = 0usize;
            for &b in &rest[..n] {
                len = (len << 8) | b as usize;
            }
            (len, &rest[n..])
        };
        if rest.len() < len {
            return None;
        }
        Some((tag, &rest[..len], &rest[len..]))
    }

    const CN_OID: &[u8] = &[0x55, 0x04, 0x03]; // id-at-commonName 2.5.4.3

    // webpki's `Cert::subject()` hands back the Name's contents — the
    // RDNs without the outer SEQUENCE. Accept a wrapped SEQUENCE too
    // so the helper works on either form.
    let mut rdns = match tlv(subject_der) {
        Some((0x30, inner, [])) => inner,
        _ => subject_der,
    };
    while !rdns.is_empty() {
        let (tag, rdn, rest) = tlv(rdns)?;
        rdns = rest;
        if tag != 0x31 {
            continue; // RDN ::= SET OF AttributeTypeAndValue
        }
        let mut atvs = rdn;
        while !atvs.is_empty() {
            let (tag, atv, rest) = tlv(atvs)?;
            atvs = rest;
            if tag != 0x30 {
                continue;
            }
            let (oid_tag, oid, atv_rest) = tlv(atv)?;
            if oid_tag != 0x06 || oid != CN_OID {
                continue;
            }
            let (val_tag, val, _) = tlv(atv_rest)?;
            return match val_tag {
                // UTF8String / PrintableString / IA5String / T61String
                // (T61 treated as Latin-1 — CN values are ASCII in
                // practice and this only feeds an equality check).
                0x0c | 0x13 | 0x16 | 0x14 => {
                    Some(String::from_utf8_lossy(val).into_owned())
                }
                // BMPString is UTF-16BE.
                0x1e => {
                    let units: Vec<u16> = val
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_be_bytes(*c))
                        .collect();
                    String::from_utf16(&units).ok()
                }
                _ => None,
            };
        }
    }
    None
}
