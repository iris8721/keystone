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
/// Longest wait for the next bytes of a response body.
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
    read_idle: Duration,
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
            read_idle: READ_IDLE_TIMEOUT,
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

    #[cfg(test)]
    pub(crate) fn read_idle(&mut self, idle: Duration) {
        self.read_idle = idle;
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
            read_idle: self.read_idle,
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
/// protocol header. JSON calls use the short total timeout, artifact
/// transfers and uploads the download timeout. Response bodies also fail
/// after `read_idle` without new bytes; request bodies have no idle limit.
#[derive(Debug, Clone)]
pub(crate) struct Transport {
    http: reqwest::Client,
    base_url: String,
    download_timeout: Duration,
    read_idle: Duration,
}

/// A response whose body reads are bounded by the transport's idle timeout.
pub(crate) struct Response {
    inner: reqwest::Response,
    read_idle: Duration,
}

impl Response {
    pub(crate) fn status(&self) -> reqwest::StatusCode {
        self.inner.status()
    }
}

impl Transport {
    fn response(&self, inner: reqwest::Response) -> Response {
        Response {
            inner,
            read_idle: self.read_idle,
        }
    }

    /// POST a JSON body and return the raw response.
    pub(crate) async fn post<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<Response, ClientError> {
        let resp = self
            .http
            .post(format!("{}{path}", self.base_url))
            .json(body)
            .send()
            .await?;
        Ok(self.response(resp))
    }

    /// GET an artifact with an `Authorization` header under the download
    /// timeout.
    pub(crate) async fn download(
        &self,
        path: &str,
        authorization: &str,
    ) -> Result<Response, ClientError> {
        let resp = self
            .http
            .get(format!("{}{path}", self.base_url))
            .header(reqwest::header::AUTHORIZATION, authorization)
            .timeout(self.download_timeout)
            .send()
            .await?;
        Ok(self.response(resp))
    }

    /// PUT a raw body with extra headers. Sending the body and waiting for
    /// the response share only the download timeout, so a slow uplink or a
    /// long server-side seal is not cut short by an idle limit.
    pub(crate) async fn upload(
        &self,
        path: &str,
        headers: HeaderMap,
        body: reqwest::Body,
    ) -> Result<Response, ClientError> {
        let resp = self
            .http
            .put(format!("{}{path}", self.base_url))
            .headers(headers)
            .body(body)
            .timeout(self.download_timeout)
            .send()
            .await?;
        Ok(self.response(resp))
    }
}

/// Read a body, failing once it exceeds `cap` bytes or no bytes arrive for
/// the idle timeout.
pub(crate) async fn read_capped(mut resp: Response, cap: u64) -> Result<Vec<u8>, ClientError> {
    let too_large = || {
        ClientError::InvalidResponse(KeystoneError::Malformed(format!(
            "body exceeds {cap} bytes"
        )))
    };
    if resp.inner.content_length().is_some_and(|len| len > cap) {
        return Err(too_large());
    }
    let idle = resp.read_idle;
    let mut buf = Vec::new();
    loop {
        let chunk = tokio::time::timeout(idle, resp.inner.chunk())
            .await
            .map_err(|_| ClientError::Stalled { idle })??;
        let Some(chunk) = chunk else {
            return Ok(buf);
        };
        if buf.len() as u64 + chunk.len() as u64 > cap {
            return Err(too_large());
        }
        buf.extend_from_slice(&chunk);
    }
}

/// Read and parse a successful JSON body.
pub(crate) async fn read_json<T: DeserializeOwned>(resp: Response) -> Result<T, ClientError> {
    let bytes = read_capped(resp, MAX_JSON_BODY).await?;
    parse_json(&bytes, "response")
}

/// Parse JSON that arrived from the server; failure is an invalid response.
pub(crate) fn parse_json<T: DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, ClientError> {
    serde_json::from_slice(bytes)
        .map_err(|e| ClientError::InvalidResponse(KeystoneError::Malformed(format!("{what}: {e}"))))
}

/// A 2xx response parsed as JSON; anything else as `ServerRejected`.
pub(crate) async fn accept_json<T: DeserializeOwned>(resp: Response) -> Result<T, ClientError> {
    if resp.status().is_success() {
        read_json(resp).await
    } else {
        Err(rejection(resp).await)
    }
}

/// Turn a non-2xx response into `ServerRejected`. A body that is not a
/// keystone `ErrorBody` yields `code: None`.
pub(crate) async fn rejection(resp: Response) -> ClientError {
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Instant;

    use axum::Router;
    use axum::body::Bytes;
    use axum::routing::put;
    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const IDLE: Duration = Duration::from_millis(200);

    fn transport(addr: SocketAddr) -> Transport {
        let mut options = TransportOptions::new(format!("http://{addr}"));
        options.allow_insecure_http();
        options.read_idle(IDLE);
        options.download_timeout(Duration::from_secs(10));
        options.build().unwrap()
    }

    #[tokio::test]
    async fn slow_upload_and_slow_server_outlast_the_idle_window() {
        async fn store(body: Bytes) -> axum::Json<Value> {
            // Stands in for sealing: no response bytes for longer than IDLE.
            tokio::time::sleep(IDLE * 2).await;
            axum::Json(serde_json::json!({ "received": body.len() }))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, Router::new().route("/up", put(store))).into_future());

        let chunks = futures_util::stream::unfold(0u8, |sent| async move {
            if sent == 5 {
                return None;
            }
            tokio::time::sleep(IDLE * 3 / 4).await;
            Some((Ok::<_, std::io::Error>(vec![sent; 100]), sent + 1))
        });
        let started = Instant::now();
        let resp = transport(addr)
            .upload("/up", HeaderMap::new(), reqwest::Body::wrap_stream(chunks))
            .await
            .expect("upload is not cut off by the idle window");
        let body: Value = accept_json(resp).await.unwrap();
        assert_eq!(body["received"], 500);
        assert!(started.elapsed() > IDLE * 4);
    }

    #[tokio::test]
    async fn stalled_response_body_fails() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 64\r\n\r\n{\"a\"",
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        let resp = transport(addr).post("/json", &()).await.unwrap();
        let started = Instant::now();
        let err = read_json::<Value>(resp).await.unwrap_err();
        assert!(
            matches!(err, ClientError::Stalled { idle } if idle == IDLE),
            "{err:?}"
        );
        assert!(err.is_retryable());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
