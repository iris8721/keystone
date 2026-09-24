//! [`AdminClient`]: operator revocations and artifact publishing against the
//! admin listener.

use std::fmt;
use std::time::Duration;

use keystone_core::wire::{
    ADMIN_TOKEN_HEADER, BUILD_ID_HEADER, MAX_ADMIN_TOKEN_BYTES, PublishBody, RevokeBody,
    RevokeRequest, RevokeTarget, paths, validate_build_id, validate_release,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ClientError;
use crate::transport::{ClientIdentity, Transport, TransportOptions, accept_json};

/// Configures an [`AdminClient`]; TLS options behave as on
/// [`crate::ClientBuilder`], and an admin token is required.
pub struct AdminClientBuilder {
    options: TransportOptions,
    admin_token: Option<Zeroizing<String>>,
}

impl fmt::Debug for AdminClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminClientBuilder")
            .field("options", &self.options)
            .field(
                "admin_token",
                &self.admin_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl AdminClientBuilder {
    /// Trust only this PEM CA for the admin listener's chain.
    pub fn server_ca_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.options.server_ca_pem(pem.into());
        self
    }

    /// Accept a listener whose leaf SPKI sha256 is `spki_sha256`; replaces
    /// hostname verification. Repeatable.
    pub fn pin_spki(mut self, spki_sha256: [u8; 32]) -> Self {
        self.options.pin_spki(spki_sha256);
        self
    }

    /// Present this certificate and key for mTLS; its hash must be on the
    /// server's admin allow-list.
    pub fn identity(mut self, identity: ClientIdentity) -> Self {
        self.options.identity(identity);
        self
    }

    /// Permit a plaintext `http://` URL. Development only.
    pub fn allow_insecure_http(mut self) -> Self {
        self.options.allow_insecure_http();
        self
    }

    /// Cap on each revocation request; default 10 s.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout(timeout);
        self
    }

    /// Cap on an artifact upload, connect through response; default 10 min.
    pub fn download_timeout(mut self, timeout: Duration) -> Self {
        self.options.download_timeout(timeout);
        self
    }

    /// The operator token the server was configured with.
    pub fn admin_token(mut self, token: impl Into<String>) -> Self {
        self.admin_token = Some(Zeroizing::new(token.into()));
        self
    }

    /// Build the client. Fails with `InvalidConfig` without an admin token,
    /// with one that is empty, over `MAX_ADMIN_TOKEN_BYTES`, or not a valid
    /// header value, or on the transport errors of
    /// [`crate::ClientBuilder::build`].
    pub fn build(self) -> Result<AdminClient, ClientError> {
        let admin_token = self
            .admin_token
            .ok_or_else(|| ClientError::config("admin token is required"))?;
        if admin_token.is_empty() || admin_token.len() > MAX_ADMIN_TOKEN_BYTES {
            return Err(ClientError::config(format!(
                "admin token must be 1 to {MAX_ADMIN_TOKEN_BYTES} bytes"
            )));
        }
        let mut token_header = HeaderValue::from_str(&admin_token)
            .map_err(|e| ClientError::config_from("admin token is not a valid header value", e))?;
        token_header.set_sensitive(true);
        Ok(AdminClient {
            transport: self.options.build()?,
            admin_token,
            token_header,
        })
    }
}

/// Client for the admin listener: `/revoke` and artifact publishing.
#[derive(Clone)]
pub struct AdminClient {
    transport: Transport,
    admin_token: Zeroizing<String>,
    token_header: HeaderValue,
}

impl fmt::Debug for AdminClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminClient")
            .field("transport", &self.transport)
            .field("admin_token", &"[redacted]")
            .finish()
    }
}

impl AdminClient {
    /// Start configuring a client for the admin listener at `admin_url`.
    pub fn builder(admin_url: impl Into<String>) -> AdminClientBuilder {
        AdminClientBuilder {
            options: TransportOptions::new(admin_url.into()),
            admin_token: None,
        }
    }

    /// Revoke one session and its children.
    pub async fn revoke_session(&self, session_id: Uuid) -> Result<RevokeBody, ClientError> {
        self.revoke(RevokeTarget::Session(session_id)).await
    }

    /// Revoke every session of `account`.
    pub async fn revoke_account(&self, account: &str) -> Result<RevokeBody, ClientError> {
        self.revoke(RevokeTarget::Account(account.to_owned())).await
    }

    /// Revoke issuer key `key_id`, killing every session. The server refuses
    /// its active signing key with `active_signing_key`.
    pub async fn revoke_key_id(&self, key_id: u8) -> Result<RevokeBody, ClientError> {
        self.revoke(RevokeTarget::KeyId(key_id)).await
    }

    async fn revoke(&self, target: RevokeTarget) -> Result<RevokeBody, ClientError> {
        let request = RevokeRequest {
            admin_token: self.admin_token.clone(),
            target,
        };
        request.validate()?;
        accept_json(self.transport.post(paths::REVOKE, &request).await?).await
    }

    /// Publish plaintext `body` as release `product`/`version` with
    /// `build_id`; the server seals and stores it. Releases are immutable:
    /// an existing version is rejected. Names are validated before sending
    /// (`Core`); the upload runs under the download timeout.
    pub async fn publish_artifact(
        &self,
        product: &str,
        version: &str,
        build_id: &str,
        body: impl Into<reqwest::Body>,
    ) -> Result<PublishBody, ClientError> {
        validate_release(product, version)?;
        validate_build_id(build_id)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(ADMIN_TOKEN_HEADER),
            self.token_header.clone(),
        );
        headers.insert(
            HeaderName::from_static(BUILD_ID_HEADER),
            HeaderValue::from_str(build_id)
                .map_err(|_| keystone_core::KeystoneError::Malformed("build id".into()))?,
        );
        let path = paths::artifact(product, version);
        accept_json(self.transport.upload(&path, headers, body.into()).await?).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_admin_token() {
        let token = "correct-horse-battery-staple-0123456789";
        let builder = AdminClient::builder("http://127.0.0.1:8444")
            .allow_insecure_http()
            .admin_token(token);
        assert!(!format!("{builder:?}").contains(token));
        let client = builder.build().unwrap();
        assert!(!format!("{client:?}").contains(token));
    }
}
