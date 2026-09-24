//! HTTP transport shared by the session and admin clients: URL policy,
//! rustls configuration with CA roots and SPKI pins, the protocol header,
//! timeouts, bounded body reads, and error-body parsing.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use keystone_core::KeystoneError;
use keystone_core::wire::{ErrorBody, PROTOCOL_HEADER, PROTOCOL_VERSION};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WebPkiServerVerifier, verify_server_cert_signed_by_trust_anchor};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::ClientError;

/// Default cap on a JSON request, well under any sane lease so a
/// blackholed connection surfaces as a failure instead of a hang.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default cap on an artifact transfer, connect through last byte.
const DEFAULT_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Longest wait for the next bytes of any response body.
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest JSON response body accepted.
const MAX_JSON_BODY: u64 = 1024 * 1024;
/// Largest error body read before giving up on parsing it.
const MAX_ERROR_BODY: u64 = 64 * 1024;

/// A client certificate chain and private key for mTLS, both PEM. The key
/// PEM is wiped on drop and never printed.
#[derive(Clone)]
pub struct ClientIdentity {
    cert_pem: Vec<u8>,
    key_pem: Zeroizing<Vec<u8>>,
}

impl ClientIdentity {
    /// Identity from a PEM certificate chain (leaf first) and a PEM private
    /// key. Parsed when the client is built.
    pub fn from_pem(cert_pem: impl Into<Vec<u8>>, key_pem: impl Into<Vec<u8>>) -> Self {
        Self {
            cert_pem: cert_pem.into(),
            key_pem: Zeroizing::new(key_pem.into()),
        }
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"[redacted]")
            .finish()
    }
}

/// Transport settings shared by [`crate::ClientBuilder`] and
/// [`crate::AdminClientBuilder`].
#[derive(Debug)]
pub(crate) struct TransportOptions {
    base_url: String,
    server_ca_pem: Option<Vec<u8>>,
    pins: Vec<[u8; 32]>,
    identity: Option<ClientIdentity>,
    allow_insecure_http: bool,
    timeout: Duration,
    download_timeout: Duration,
}

impl TransportOptions {
    pub(crate) fn new(base_url: String) -> Self {
        Self {
            base_url,
            server_ca_pem: None,
            pins: Vec::new(),
            identity: None,
            allow_insecure_http: false,
            timeout: DEFAULT_TIMEOUT,
            download_timeout: DEFAULT_DOWNLOAD_TIMEOUT,
        }
    }

    pub(crate) fn server_ca_pem(&mut self, pem: Vec<u8>) {
        self.server_ca_pem = Some(pem);
    }

    pub(crate) fn pin_spki(&mut self, sha256: [u8; 32]) {
        self.pins.push(sha256);
    }

    pub(crate) fn identity(&mut self, identity: ClientIdentity) {
        self.identity = Some(identity);
    }

    pub(crate) fn allow_insecure_http(&mut self) {
        self.allow_insecure_http = true;
    }

    pub(crate) fn timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub(crate) fn download_timeout(&mut self, timeout: Duration) {
        self.download_timeout = timeout;
    }

    /// Validate the URL policy and build the HTTP client. `http://` needs
    /// `allow_insecure_http` and no TLS options; any other scheme fails.
    pub(crate) fn build(self) -> Result<Transport, ClientError> {
        let base_url = self.base_url.trim_end_matches('/').to_string();
        let url = reqwest::Url::parse(&base_url)
            .map_err(|e| ClientError::config_from(format!("base URL {base_url}"), e))?;
        if url.host_str().is_none() {
            return Err(ClientError::config(format!(
                "base URL {base_url} has no host"
            )));
        }
        let tls = match url.scheme() {
            "https" => true,
            "http" if !self.allow_insecure_http => {
                return Err(ClientError::config(format!(
                    "base URL {base_url} is plaintext http; https is required unless allow_insecure_http is set"
                )));
            }
            "http" => {
                if self.server_ca_pem.is_some() || !self.pins.is_empty() || self.identity.is_some()
                {
                    return Err(ClientError::config("TLS options require an https base URL"));
                }
                false
            }
            other => {
                return Err(ClientError::config(format!(
                    "unsupported URL scheme {other}"
                )));
            }
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(PROTOCOL_HEADER),
            HeaderValue::from(PROTOCOL_VERSION),
        );
        let mut builder = reqwest::Client::builder()
            .timeout(self.timeout)
            .read_timeout(READ_IDLE_TIMEOUT)
            .default_headers(headers);
        if tls {
            builder = builder.use_preconfigured_tls(self.tls_config()?);
        }
        let http = builder
            .build()
            .map_err(|e| ClientError::config_from("HTTP client", e))?;
        Ok(Transport {
            http,
            base_url,
            download_timeout: self.download_timeout,
        })
    }

    fn tls_config(&self) -> Result<rustls::ClientConfig, ClientError> {
        // Explicit provider, so the process-wide default is never consulted.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let ca_roots = self.server_ca_pem.as_deref().map(ca_roots).transpose()?;

        let verifier: Arc<dyn ServerCertVerifier> = if self.pins.is_empty() {
            let roots = ca_roots
                .unwrap_or_else(|| webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect());
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|e| ClientError::config_from("server verifier", e))?
        } else {
            Arc::new(PinnedVerifier {
                roots: ca_roots,
                pins: self.pins.clone(),
                algorithms: provider.signature_verification_algorithms,
            })
        };

        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ClientError::config_from("TLS versions", e))?
            .dangerous()
            .with_custom_certificate_verifier(verifier);
        let Some(identity) = &self.identity else {
            return Ok(builder.with_no_client_auth());
        };
        let certs = CertificateDer::pem_slice_iter(&identity.cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ClientError::config_from("client certificate PEM", e))?;
        if certs.is_empty() {
            return Err(ClientError::config(
                "no certificate in client certificate PEM",
            ));
        }
        let key = PrivateKeyDer::from_pem_slice(&identity.key_pem)
            .map_err(|e| ClientError::config_from("client key PEM", e))?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| ClientError::config_from("client identity", e))
    }
}

fn ca_roots(pem: &[u8]) -> Result<RootCertStore, ClientError> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(|e| ClientError::config_from("CA PEM", e))?;
        roots
            .add(cert)
            .map_err(|e| ClientError::config_from("CA certificate", e))?;
    }
    if roots.is_empty() {
        return Err(ClientError::config("no certificate in CA PEM"));
    }
    Ok(roots)
}

/// Server verification when SPKI pins are configured: the leaf key must
/// match a pin, which replaces the hostname check. With a CA configured the
/// chain (signatures, validity, usage) must still verify against it.
#[derive(Debug)]
struct PinnedVerifier {
    roots: Option<RootCertStore>,
    pins: Vec<[u8; 32]>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        if let Some(roots) = &self.roots {
            verify_server_cert_signed_by_trust_anchor(
                &cert,
                roots,
                intermediates,
                now,
                self.algorithms.all,
            )?;
        }
        let spki: [u8; 32] = Sha256::digest(cert.subject_public_key_info()).into();
        if self.pins.contains(&spki) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// A built HTTP client bound to one base URL; every request carries the
/// protocol header. JSON calls use the short timeout, artifact transfers
/// the download timeout; both give up after 30 s without new bytes.
#[derive(Debug, Clone)]
pub(crate) struct Transport {
    http: reqwest::Client,
    base_url: String,
    download_timeout: Duration,
}

impl Transport {
    /// POST a JSON body and return the raw response.
    pub(crate) async fn post<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<reqwest::Response, ClientError> {
        Ok(self
            .http
            .post(format!("{}{path}", self.base_url))
            .json(body)
            .send()
            .await?)
    }

    /// GET an artifact with an `Authorization` header under the download
    /// timeout.
    pub(crate) async fn download(
        &self,
        path: &str,
        authorization: &str,
    ) -> Result<reqwest::Response, ClientError> {
        Ok(self
            .http
            .get(format!("{}{path}", self.base_url))
            .header(reqwest::header::AUTHORIZATION, authorization)
            .timeout(self.download_timeout)
            .send()
            .await?)
    }

    /// PUT a raw body with extra headers under the download timeout.
    pub(crate) async fn upload(
        &self,
        path: &str,
        headers: HeaderMap,
        body: reqwest::Body,
    ) -> Result<reqwest::Response, ClientError> {
        Ok(self
            .http
            .put(format!("{}{path}", self.base_url))
            .headers(headers)
            .body(body)
            .timeout(self.download_timeout)
            .send()
            .await?)
    }
}

/// Read a body, failing once it exceeds `cap` bytes.
pub(crate) async fn read_capped(
    mut resp: reqwest::Response,
    cap: u64,
) -> Result<Vec<u8>, ClientError> {
    let too_large = || {
        ClientError::InvalidResponse(KeystoneError::Malformed(format!(
            "body exceeds {cap} bytes"
        )))
    };
    if resp.content_length().is_some_and(|len| len > cap) {
        return Err(too_large());
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() as u64 + chunk.len() as u64 > cap {
            return Err(too_large());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Read and parse a successful JSON body.
pub(crate) async fn read_json<T: DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, ClientError> {
    let bytes = read_capped(resp, MAX_JSON_BODY).await?;
    parse_json(&bytes, "response")
}

/// Parse JSON that arrived from the server; failure is an invalid response.
pub(crate) fn parse_json<T: DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, ClientError> {
    serde_json::from_slice(bytes)
        .map_err(|e| ClientError::InvalidResponse(KeystoneError::Malformed(format!("{what}: {e}"))))
}

/// A 2xx response parsed as JSON; anything else as `ServerRejected`.
pub(crate) async fn accept_json<T: DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, ClientError> {
    if resp.status().is_success() {
        read_json(resp).await
    } else {
        Err(rejection(resp).await)
    }
}

/// Turn a non-2xx response into `ServerRejected`. A body that is not a
/// keystone `ErrorBody` yields `code: None`.
pub(crate) async fn rejection(resp: reqwest::Response) -> ClientError {
    let status = resp.status().as_u16();
    let body = read_capped(resp, MAX_ERROR_BODY)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ErrorBody>(&bytes).ok());
    match body {
        Some(body) => ClientError::ServerRejected {
            status,
            code: Some(body.code),
            message: body.message,
        },
        None => ClientError::ServerRejected {
            status,
            code: None,
            message: format!("HTTP {status} without a keystone error body"),
        },
    }
}
