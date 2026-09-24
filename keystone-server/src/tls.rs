//! TLS plumbing: the rustls server config (optionally demanding client
//! certificates) and an axum-server acceptor that attaches the peer's
//! certificate chain to every request on the connection.

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tower_service::Service;

use crate::error::ServerError;

/// The peer's certificate chain (leaf first), inserted into request
/// extensions by [`PeerCertAcceptor`]. Empty when the client presented none.
#[derive(Clone, Debug)]
pub struct PeerCertificates(Arc<Vec<CertificateDer<'static>>>);

impl PeerCertificates {
    /// Whether the client presented no certificate.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// sha256 of the leaf certificate DER, the value sessions bind to.
    pub fn leaf_sha256(&self) -> Option<[u8; 32]> {
        self.0
            .first()
            .map(|leaf| Sha256::digest(leaf.as_ref()).into())
    }

    /// Subject common name of the leaf certificate.
    pub fn leaf_common_name(&self) -> Option<String> {
        let leaf = self.0.first()?;
        let cert = webpki::EndEntityCert::try_from(leaf).ok()?;
        subject_common_name(cert.subject())
    }
}

/// How the server listens, decided once at startup. Only `MutualTls` is a
/// production configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportMode {
    /// TLS with client certificates required and verified against `ca`.
    MutualTls {
        /// Server certificate chain PEM.
        cert: PathBuf,
        /// Server private key PEM.
        key: PathBuf,
        /// Client CA certificate PEM.
        ca: PathBuf,
    },
    /// TLS without client authentication; development only.
    TlsOnly {
        /// Server certificate chain PEM.
        cert: PathBuf,
        /// Server private key PEM.
        key: PathBuf,
    },
    /// Cleartext HTTP; development only.
    Plain,
}

/// Decide the transport from `KEYSTONE_TLS_CERT`, `KEYSTONE_TLS_KEY`, and
/// `KEYSTONE_CA_CERT`. Anything short of mTLS needs `allow_insecure`; a
/// half-configured cert/key pair is always a `Config` error.
pub(crate) fn transport_mode(
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    allow_insecure: bool,
) -> Result<TransportMode, ServerError> {
    let (cert, key) = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => (cert, key),
        (None, None) if allow_insecure => {
            if ca_cert.is_some() {
                return Err(ServerError::config(
                    "KEYSTONE_CA_CERT",
                    "set without KEYSTONE_TLS_CERT/KEYSTONE_TLS_KEY",
                ));
            }
            return Ok(TransportMode::Plain);
        }
        (None, None) => {
            return Err(ServerError::config(
                "KEYSTONE_TLS_CERT",
                "required unless KEYSTONE_ALLOW_INSECURE=1",
            ));
        }
        (Some(_), None) => {
            return Err(ServerError::config(
                "KEYSTONE_TLS_KEY",
                "required when KEYSTONE_TLS_CERT is set",
            ));
        }
        (None, Some(_)) => {
            return Err(ServerError::config(
                "KEYSTONE_TLS_CERT",
                "required when KEYSTONE_TLS_KEY is set",
            ));
        }
    };
    match ca_cert {
        Some(ca) => Ok(TransportMode::MutualTls { cert, key, ca }),
        None if allow_insecure => Ok(TransportMode::TlsOnly { cert, key }),
        None => Err(ServerError::config(
            "KEYSTONE_CA_CERT",
            "required unless KEYSTONE_ALLOW_INSECURE=1",
        )),
    }
}

/// Build the server TLS config from PEM bytes. With `ca_cert_pem`, client
/// certificates are required and verified against it; without, no client
/// authentication is requested.
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
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no private key in server key PEM",
            )
        })?;

    // Explicit provider: the process may link more than one rustls provider.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let builder = match ca_cert_pem {
        Some(ca_pem) => {
            let mut roots = RootCertStore::empty();
            let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &ca_pem[..])
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
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
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
    // Declared so h2-capable clients do not try to negotiate h2.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

/// An [`Accept`] that runs the rustls handshake, then attaches the peer
/// certificate chain to every request on the connection.
#[derive(Clone)]
pub struct PeerCertAcceptor {
    inner: RustlsAcceptor,
}

impl PeerCertAcceptor {
    /// Wrap a rustls config.
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
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let future = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = future.await?;
            // The chain is a property of the connection: capture it once.
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

/// Per-connection service wrapper that stamps [`PeerCertificates`] onto
/// each request's extensions.
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

/// The common name in the contents of a DER X.501 Name (the RDN sequence
/// without its outer SEQUENCE, as webpki returns a certificate subject), or
/// `None` when no CN is present or its string type is not supported.
fn subject_common_name(rdn_sequence: &[u8]) -> Option<String> {
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

    let mut rdns = rdn_sequence;
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
                // UTF8/Printable/IA5/T61 strings; invalid UTF-8 yields no name, never a lossy one.
                0x0c | 0x13 | 0x16 | 0x14 => String::from_utf8(val.to_vec()).ok(),
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
