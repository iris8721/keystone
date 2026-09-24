# keystone

Server-authoritative licensing for distributed software. The server decides what runs; clients hold only signed, expiring, revocable evidence of that decision.

Rust, no `unsafe`, rustls with ring. Wire protocol version 2.

## Crates

| Crate | Contents |
|---|---|
| `keystone-core` | Envelopes, request MACs, replay sets, lease state machine, handoff tokens, payload keys, owner-only file writes, `wire` (DTOs, error codes, MAC contexts, paths) |
| `keystone-server` | axum server, storage traits with in-memory defaults, `keystone-server` binary (feature `cli`, default) |
| `keystone-client` | `KeystoneClient` (loader and application), `AdminClient`, `SessionGate`, handoff transport |
| `xtask` | Operator tooling: keys, CA, certificates, accounts, sealing, verification, local dev, deploy |

## Flow

```
Loader ─ POST /exchange ─────────────────► Server   credentials → session, lease, features
Loader ─ POST /handoff ──────────────────► Server   single-use handoff credential
Loader ─ HandoffToken over stdin ────────► App
App    ─ POST /attest ───────────────────► Server   consumes the handoff → child session
App    ─ POST /heartbeat (loop) ─────────► Server   renewed lease, live features
App    ─ POST /payload, GET /payload/… ──► Server   signed manifest + wrapped key, sealed blob
Admin  ─ POST /revoke, PUT /artifacts/… ─► Server   admin listener
```

Every response that grants access is an ed25519 envelope bound to a nonce the verifier minted. Error bodies are unsigned; they can only end or refuse access. Session-bound requests carry an HMAC over the session id, a nonce, a millisecond timestamp and the operation: under the session key, or under the handoff secret for `/attest`. Admin requests need an allow-listed client certificate and the admin token. Every request carries `keystone-protocol: 2`.

## Guarantees

| Property | Mechanism |
|---|---|
| Responses can't be forged | ed25519 over domain-separated canonical bytes; issuer keys compiled into the client (`TrustedIssuers`) |
| Responses can't be replayed | Challenge echoed in the signature, 60 s challenge TTL on a monotonic clock, per-session consumed set |
| Requests can't be replayed | MAC'd nonce + timestamp, ±5 min window, nonce consumed exactly once |
| Sessions can't outlive entitlement | Grant re-resolved on every attest, heartbeat and payload request; lease capped by grant expiry |
| Sessions can't be resurrected | `Dead` is final on client and server; late responses are discarded |
| Session material is bound to its certificate | Every session records the mTLS leaf that created it; every later request must present it; the leaf CN must equal the account |
| Handoffs are single-use | Server-minted handoff credential consumed on attest; the application gets its own child session; the loader key stays in the loader |
| Sessions are scoped to one product | Payload requests for another product fail with `wrong_product` |
| Revocation reaches descendants | Revoking a session, account or key kills every child session created from it |
| A leaked issuer key is containable | Revocation persisted and carried in every signed body; the active key cannot be revoked |
| A leaked payload secret is containable | Artifact keys derive over an epoch; bump + reseal |
| Payloads are session-gated | Signed manifest `{sha256, build_id, download_id}`; artifact key wrapped under session material |
| Leaks are attributable | Per-release `build_id`, per-request `download_id`, owner-only pseudonymous download log |
| Abuse is bounded | Per-IP (IPv6 per /64), per-session and failed-login limits; limits charged only after authentication where possible; 16 KiB bodies; field caps |
| Insecure setups are explicit | Plain HTTP, TLS without client certificates, ephemeral keys and dev accounts require `KEYSTONE_ALLOW_INSECURE=1` |

Non-goals: HWID is an anomaly signal, not identity. Client certificates are extractable under instrumentation. Anything the application can do without a fresh lease is unprotected.

Secret files (accounts, revocations, download log, keys) are written owner-only on every OS.

## Operator setup

```sh
cargo xtask ca                                   # private CA for server and client certificates
cargo xtask keygen --key-id 1                    # keystone-1.key; prints the pubkey clients trust
cargo xtask cert --host keystone.example.com     # prints the server SPKI clients pin
cargo xtask payload-secret
cargo xtask account add alice                    # prompts for the secret
cargo xtask account grant alice --product studio --days 30 --features render,export
cargo xtask issue-cert alice                     # client certificate; pins it on the account
cargo xtask issue-cert operator                  # admin client certificate; add its hash to KEYSTONE_ADMIN_CERT_SHA256
cargo xtask seal --product studio --version 1.0.0 --in studio.bin
cargo xtask verify                               # preflight
```

`cargo xtask dev` provisions a CA, server and admin certificates, a dev account in `dev-accounts.json`, and a payload secret, then runs the server with mTLS and the admin listener.

Artifacts live at `payloads/<product>/<version>.bin` with `.sha256` and `.build` sidecars. `xtask seal` or `AdminClient::publish_artifact` writes all three. Releases are immutable.

## Configuration

| Variable | Default | |
|---|---|---|
| `KEYSTONE_BIND` | `0.0.0.0:8443` | Public listener |
| `KEYSTONE_ADMIN_BIND` | `127.0.0.1:8444` | Admin listener; started only with `KEYSTONE_ADMIN_TOKEN` |
| `KEYSTONE_ADMIN_TOKEN` | unset | At least 32 characters, at most 1024 bytes |
| `KEYSTONE_ADMIN_CERT_SHA256` | unset | Comma-separated sha256 (hex) of admin client certificates; required with the admin token under mTLS |
| `KEYSTONE_KEYFILE` | required | 33-byte key file (key id + seed) |
| `KEYSTONE_REVOKED_KEY_IDS` | empty | Comma-separated key ids |
| `KEYSTONE_REVOCATIONS_FILE` | `revoked-keys.json` | Persisted runtime revocations |
| `KEYSTONE_TLS_CERT`, `KEYSTONE_TLS_KEY` | required | Server certificate and key |
| `KEYSTONE_CA_CERT` | required | Client CA (mTLS) |
| `KEYSTONE_ACCOUNTS` | `./accounts.json` | Account file |
| `KEYSTONE_PAYLOAD_DIR`, `KEYSTONE_PAYLOAD_SECRET_FILE` | unset | Both or neither; payload routes and publishing off without them |
| `KEYSTONE_PAYLOAD_EPOCH` | `0` | Key-derivation epoch |
| `KEYSTONE_WATERMARK_SECRET` | derived from the payload secret | 64 hex characters |
| `KEYSTONE_DOWNLOAD_LOG` | unset | JSONL path |
| `KEYSTONE_LEASE_TTL_SECS` | `300` | |
| `KEYSTONE_GRACE_SECS` | `60` | |
| `KEYSTONE_RATE_<LIMIT>` | see `RateLimits` | `EXCHANGE_PER_IP`, `EXCHANGE_FAILURES_PER_ACCOUNT`, `EXCHANGE_FAILURES_PER_ACCOUNT_TOTAL`, `SESSION_PER_IP`, `HANDOFF_PER_SESSION`, `ATTEST_PER_SESSION`, `HEARTBEAT_PER_SESSION`, `PAYLOAD_FETCH_PER_SESSION`, `PAYLOAD_DOWNLOAD_PER_SESSION`, `ADMIN_FAILURES_PER_IP` |
| `KEYSTONE_ALLOW_INSECURE` | `0` | `1` permits plain HTTP, TLS without client certs, an ephemeral key, `KEYSTONE_DEV_SEED` |
| `KEYSTONE_DEV_SEED` | `0` | `1` serves built-in dev accounts; requires `KEYSTONE_ALLOW_INSECURE=1` |
| `RUST_LOG` | `info` | |

Invalid values stop startup. The server refuses to start when the active key id is revoked.

## Client integration

The issuer set and the server SPKI pins are compiled into each binary. Nothing trust-related is read from the handoff, argv, env or the loader.

Loader:

```rust
let client = KeystoneClient::builder(URL, TrustedIssuers::from_public_keys([(1, ISSUER_1)])?)
    .server_ca_pem(CA_PEM)
    .pin_spki(SERVER_SPKI)
    .pin_spki(NEXT_SERVER_SPKI)
    .identity(ClientIdentity::from_pem(cert_pem, key_pem))
    .build()?;

let session = client.exchange("alice", &secret, "studio", hwid).await?;
let token = client.create_handoff(&session, "studio", DEFAULT_HANDOFF_TTL).await?;
let child = keystone_client::handoff::spawn_with_handoff(&mut Command::new("studio"), &token)?;
```

Application (its own client, built like the loader's with the same account certificate from the install; the certificate never travels in the handoff):

```rust
let pending = PendingSession::from_handoff(HandoffToken::read_from(std::io::stdin())?, "studio")?;
let session = client.attest(pending).await?;
let gate = session.gate();

let payload = client.download_payload(&session, "studio", "1.0.0").await?;
tokio::spawn({
    let (client, session) = (client.clone(), session.clone());
    async move { client.run_keepalive(&session).await }
});

// at every protected operation
gate.authorize()?;
if gate.has_feature("export") { /* … */ }
```

`ClientSession` is a cheap `Clone + Send + Sync` handle; keepalive and requests share it. `SessionGate` is a read-only view that never touches the network. `run_keepalive` renews the lease, retries with jittered backoff inside the fixed grace deadline, and returns the `DeadReason` when the session ends.

JSON calls time out after 10 s (`ClientBuilder::timeout`); artifact transfers after 10 min (`download_timeout`); any response stalled for 30 s fails.

Errors carry the server's `ErrorCode`. `ClientError::is_retryable` and `ErrorCode::verdict` decide what happens to the session:

| Code | HTTP | Verdict |
|---|---|---|
| `stale_request`, `replay`, `rate_limited`, `artifact_not_found`, `backend_unavailable` | 401/409/429/404/503 | transient |
| `unknown` and unrecognized codes | 500 | transient |
| `invalid_mac` | 401 | dead (`Rejected`) |
| `unknown_session` | 404 | dead (`UnknownSession`, e.g. server restart) |
| `session_revoked`, `no_entitlement` | 403 | dead (`Revoked`) |
| `session_expired`, `grace_exhausted` | 410 | dead |
| `invalid_credentials`, `wrong_product`, `handoff_invalid`, `artifact_invalid`, `unsupported_protocol`, `bad_request`, `forbidden`, `active_signing_key`, `conflict` | 400/401/403/409/422/500 | request error, session untouched |

A non-2xx response without a keystone error body is transient.

## Embedding the server

```rust
let config = ServerConfig::from_env()?;
let (builder, listeners) = config.into_parts(Arc::new(MyEntitlements::new(pool.clone())))?;
let state = builder
    .revocations(Arc::new(MyRevocations::new(pool)))
    .audit(Arc::new(MyAudit::new()))
    .build()
    .await?;
keystone_server::serve(state, listeners, shutdown_signal()).await?;
```

Depend on `keystone-server` with `default-features = false`. `into_parts` loads TLS, binds the listeners and returns an `AppStateBuilder` populated from the environment; override any seam before `build`. Storage and observability are traits: `EntitlementSource`, `SessionStore`, `RateLimiter`, `RevocationStore`, `AuditSink`. `AppState::{revoke_session, revoke_account, revoke_key_id}` revoke programmatically.

`public_router` and `admin_router` can be mounted directly. Requests must carry `ConnectInfo<SocketAddr>`, and, when client certificates are required, `tls::PeerCertificates` from `tls::PeerCertAcceptor`; without them the routes answer 500. `serve` provides both.

Session state is in memory by default; a restart ends every session with `unknown_session`. Run one replica with the in-memory store.

## Administration

```rust
let admin = AdminClient::builder("https://127.0.0.1:8444")
    .server_ca_pem(CA_PEM)
    .identity(operator_identity)
    .admin_token(token)
    .build()?;
admin.revoke_account("alice").await?;
admin.publish_artifact("studio", "1.1.0", "studio-1.1.0-a1b2c3", tokio::fs::File::open("studio.bin").await?).await?;
```

Revocation targets: a session (and its child sessions), an account, or an issuer key id. Key revocations persist through the `RevocationStore`. Publishing seals the plaintext under the current epoch; an existing version is refused with `conflict`.

## Key rotation

1. `cargo xtask keygen --key-id 2`; ship clients trusting `{1, 2}`.
2. Point `KEYSTONE_KEYFILE` at `keystone-2.key`; restart.
3. Revoke key id 1.

Compromise of the active key: steps 2 then 3 immediately. The server rejects revocation of the key it signs with.

## TLS rotation

1. `cargo xtask tls-key --out next-server-key.pem`; ship clients pinning the current and printed SPKI.
2. `cargo xtask cert --key next-server-key.pem --force --host …`; restart.

`cargo xtask spki <pem>` prints the pin for any certificate or key.

## Testing

```sh
cargo test --workspace
```

## License

MIT.
