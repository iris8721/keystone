# Changelog

## 0.2.0

Wire protocol 2. Not compatible with 0.1 clients, servers, key files or artifact layouts.

### Security
- Every session is bound to the mTLS certificate that created it; the certificate CN must equal the account.
- Payload requests are restricted to the session's product.
- Handoffs are server-minted and single-use; the application receives its own child session and never the loader's key.
- Revoking a session, account or issuer key also kills every child session created from it; an exchange racing an account revocation is revoked.
- Failed logins: a slot is reserved before the password check and refunded on success, so concurrent guesses cannot exceed the limit. Under mTLS the limit is per account; without client certificates it is per account and client address, with an account-wide ceiling. Certificates that may not act for an account are charged to the presenter, not the account.
- Per-session limits are charged only after the certificate and MAC checks; attest checks the limit before spending the handoff.
- Session buckets exist only for existing sessions; session routes have a per-IP limit; IPv6 is bucketed per /64; a full limiter never denies tracked keys.
- 16 KiB request bodies; field length caps on every request.
- Admin routes are on a separate listener and require an allow-listed client certificate (`KEYSTONE_ADMIN_CERT_SHA256`) and an admin token of at least 32 characters and at most 1024 bytes; only failed tokens are rate-limited.
- The active signing key cannot be revoked; startup fails if it is revoked; runtime key revocations persist.
- Replay window closed at the nonce expiry boundary; wire timestamps and durations are integer milliseconds.
- Exchange responses are rejected once `issued_at` plus the measured round trip passes their expiry.
- Artifacts are streamed and never decrypted server-side.
- Routers fail closed without the peer address or, when required, the client certificate.
- Artifact names reject Windows device names (`CON`, `NUL`, `COM1`, …) and trailing dots.
- Session keys, handoff secrets, artifact keys, seeds and admin tokens are zeroized.
- Account files, revocation files and the download log are written owner-only on every OS; the watermark secret is derived from, not equal to, the payload secret; `download_id` covers the request nonce.

### Added
- `keystone_core::wire`: request/response types, `ErrorCode` (incl. `conflict`), `Verdict`, MAC contexts, paths, `DownloadAuthorization`, protocol header.
- `keystone_core::{fs, revocations}`: owner-only atomic writes, revocation file format.
- `POST /handoff`, `HandoffToken` (stdin transport), `PendingSession`, child sessions.
- Artifact publishing: admin `PUT /artifacts/{product}/{version}`, `AdminClient::publish_artifact`; `payload::MAX_PLAINTEXT_BYTES`.
- `SessionGate`, `ClientSession::features`, `KeystoneClient::run_keepalive`, `AdminClient`, `ClientError::{is_retryable, Stalled}`.
- `ClientBuilder` with multiple SPKI pins, a separate `download_timeout`, and an idle timeout on response bodies.
- `TrustedIssuers::from_public_keys`; `VerifyingKey` re-exported.
- Server storage traits: `SessionStore`, `RateLimiter`, `RevocationStore`, `AuditSink`; `AppState::builder`; `ServerConfig::into_parts`; `serve` with graceful shutdown; `ServerError`.
- Configurable lease, grace and rate limits (`KEYSTONE_LEASE_TTL_SECS`, `KEYSTONE_GRACE_SECS`, `KEYSTONE_RATE_*`).
- xtask: `tls-key`, `spki`, repeatable `cert --host`, `cert --key`, key reuse across re-issue; `dev` provisions mTLS and the admin listener.

### Changed
- Key file is 33 bytes (key id + seed); `keygen` writes `keystone-<id>.key`; `Issuer::generate` takes the key id.
- Artifact layout `payloads/<product>/<version>.bin` with required `.sha256` and `.build` sidecars; releases are immutable.
- Features travel in exchange, attest and heartbeat responses; manifests no longer carry them.
- Every signed body carries `server_time` and the revoked issuer key ids.
- Exchange tolerates any client clock offset; session clocks are monotonic.
- A restarted server reports `unknown_session` (`DeadReason::UnknownSession`).
- `ClientSession` is a shared handle with `&self` methods; `attest` takes only the `PendingSession`.
- `EntitlementSource` returns `BackendError`.
- The server binary is behind the default `cli` feature.

### Removed
- Environment: `KEYSTONE_PORT` (use `KEYSTONE_BIND`), `KEYSTONE_KEY_ID` and `KEYSTONE_SEED` (use `KEYSTONE_KEYFILE`), `KEYSTONE_PAYLOAD_SECRET` (use `KEYSTONE_PAYLOAD_SECRET_FILE`).
- keystone-server: `build_router` (use `public_router`/`admin_router`), `runtime`.
- keystone-client: `KeystoneClient::{new, new_insecure, new_unpinned_webpki, revoke}`; `ClientSession::{clock_drift, consume_nonce, is_nonce_consumed, make_handoff, from_handoff}`; `ClientError::{GraceExhausted, MissingSessionKey, InsecureBaseUrl, Tls}`; the `client`, `error` and `session` module paths; re-exports of `Handoff` and `HandoffPayload`.
- keystone-core: `Issuer::{from_seed, generate_with_id}`, `artifact_key_for`, `wrap_artifact_key`, `Manifest::{feature_grants, has_feature}`, `Challenge::{fresh, from_parts, issued_at, ttl}`, `crypto::DOMAIN_KEY_WRAP`; `Handoff`, `artifact_key` and `derive_payload_key` are no longer public.
