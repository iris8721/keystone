# keystone

Server-authoritative authentication for paid software. The server decides
what is allowed; authorization is limited, revocable, and bound to each
operation. A license key never becomes a permanent bearer token, a loader
never becomes a source of trust, and nothing valuable works offline.

Rust workspace, no unsafe, 220 tests. Distilled from the PROBE writeup
*Authentication For Dummies* (`writeup/`) and an RSW post-mortem.

## Flow

```
User ─► Client ──(1) exchange──────────► Server
          │ ◄──(2) signed session ───────┘
          │
          └──(3) encrypted handoff──► Application
                                        │ ──(4) attest ─────────► Server
                                        │ ◄──(5) signed lease ───┘
                                        │
                                        └─ loop ──(6) heartbeat ─► Server
                                             ◄──(7) lease refresh ─┘
```

Every arrow from the server is a signed envelope bound to a nonce the
verifier minted. Every arrow to the server after exchange carries a MAC
under the session key over the session id, a fresh nonce, a timestamp, and
the operation. The application performs its own attestation — it never
trusts "the client already checked".

## Guarantees

| Property | Mechanism |
|---|---|
| Responses can't be forged | ed25519 over domain-separated canonical bytes; verifier holds a compiled-in `TrustedIssuers` set keyed by `key_id` |
| Responses can't be replayed | verifier-minted challenge echoed in the signature; server-side and client-side consumed sets |
| Requests can't be replayed | client nonce + `issued_at` inside the MAC; accepted within ±5 min; nonce remembered exactly that long |
| Sessions can't outlive entitlement | grants re-resolved live on every attest/heartbeat; lease capped by grant expiry |
| Sessions can't be resurrected | `Grace → Dead` is a core state transition; a late heartbeat response is discarded |
| Stolen session material is useless | mTLS with per-account cert pinned at exchange and required on every session-bound route |
| A leaked issuer key is containable | `/revoke {key_id}` kills trust and every session; clients holding the successor key keep working; revocations propagate in signed bodies |
| A leaked payload secret is containable | artifact keys derive over an epoch; bump + reseal makes every prior blob unopenable |
| Payloads are session-gated | signed manifest `{sha256, build_id, download_id, feature_grants}`; artifact key wrapped under session material; verify-before-return |
| Leaks are attributable | per-release `build_id` and per-request `download_id`, both signed; pseudonymous JSONL download log |
| Insecure transport can't happen by accident | plain HTTP and TLS-without-mTLS refuse to start unless `KEYSTONE_ALLOW_INSECURE=1` |

Non-goals, by design: HWID is an anomaly signal, not identity. Client
certs are extractable under instrumentation — a cost-raiser. Anything the
payload can do without a fresh lease is unprotected.

## Layout

| Crate | Role |
|---|---|
| `keystone-core` | envelopes, manifests, `TrustedIssuers`, session state machine, replay cache, request MACs, HKDF payload keys, sealed handoff |
| `keystone-server` | axum: `/exchange` `/attest` `/heartbeat` `/revoke` `POST /payload` `GET /payload/{p}/{v}`; in-memory session store; local accounts file; mTLS |
| `keystone-client` | `KeystoneClient` SDK: pinned TLS, exchange/attest/heartbeat, handoff seal/open, manifest + payload fetch |
| `xtask` | operator tooling: keygen, CA, certs, accounts, seal, verify, dev, deploy |

Sessions are in-memory on purpose: restart is a clean re-exchange.

## Operator setup

```sh
cargo xtask ca                          # private CA
cargo xtask keygen --key-id 1           # issuer seed → prints (key_id, pubkey)
cargo xtask cert                        # server cert → prints SPKI sha256
cargo xtask payload-secret
cargo xtask account add alice           # hidden prompt for the secret
cargo xtask account grant alice --product aimbot --days 30 --features esp,aimbot
cargo xtask issue-cert alice            # mTLS client cert, CN=alice
cargo xtask seal --product aimbot --version 1.0.0 --in aimbot.bin --out payloads/
cargo xtask verify                      # preflight
```

```
KEYSTONE_KEYFILE=keystone.key           KEYSTONE_KEY_ID=1
KEYSTONE_REVOKED_KEY_IDS=               KEYSTONE_TLS_CERT=keystone-cert.pem
KEYSTONE_TLS_KEY=keystone-key.pem       KEYSTONE_CA_CERT=keystone-ca-cert.pem
KEYSTONE_ACCOUNTS=accounts.json         KEYSTONE_PAYLOAD_DIR=payloads/
KEYSTONE_PAYLOAD_SECRET_FILE=payload.secret
KEYSTONE_PAYLOAD_EPOCH=0                KEYSTONE_ADMIN_TOKEN=<random>
KEYSTONE_DOWNLOAD_LOG=downloads.jsonl   KEYSTONE_PORT=8443
```

`cargo xtask dev` provisions all of it for local testing.

## Integration

The trust root is compiled in. `TrustedIssuers` is never read from the
handoff, argv, env, or anything the loader touched.

```rust
let issuers = TrustedIssuers::new([(1, key_1), (2, key_2)]);   // mid-rotation: both
let client = KeystoneClient::new(url, issuers, ca_pem, server_spki_sha256, Some(identity))?;
```

**Loader**

```rust
let mut session = client.exchange("alice", &secret, "aimbot", hwid).await?;
let (blob, handoff_key) = session.make_handoff("aimbot.exe", Duration::minutes(2))?;
// deliver blob + handoff_key via env / argv / shared memory — your choice
```

**Payload** — its own client, its own baked issuers, its own attestation:

```rust
let client = KeystoneClient::new(url, TrustedIssuers::single(1, BAKED_PUBKEY), ca_pem, spki, Some(identity))?;
let mut session = ClientSession::from_handoff(&handoff_key, &blob, "aimbot.exe", Utc::now())?;
client.attest(&mut session, "aimbot.exe").await?;                 // authorize() is NotAuthenticated until this
let (manifest, _key) = client.fetch_manifest(&mut session, "aimbot", "1.0.0").await?;
let bytes = client.download_payload(&mut session, "aimbot", "1.0.0").await?;   // verified or nothing
if session.has_feature(&manifest.manifest, "esp", Utc::now()) { /* … */ }
```

**Keepalive**

```rust
loop {
    session.authorize()?;                                   // at every gate, not just startup
    if session.next_heartbeat_due(Utc::now()).is_some_and(|d| d <= Utc::now()) {
        match client.heartbeat(&mut session).await {
            Ok(_) => {}
            Err(_) if !session.is_alive() => break,         // dead is final
            Err(_) => {}                                    // transient → grace, deadline fixed
        }
    }
}
```

Transient codes (`artifact_not_found`, `session_not_active`,
`rate_limited`, `stale_request`) enter grace. 401/403/404/410 kill. Grace
has a fixed deadline; retries never extend it.

## Key rotation

Planned: `keygen --key-id 2` → ship clients trusting `{1, 2}` → switch the
server to `KEYSTONE_KEY_ID=2` → once no key-1 clients remain,
`KEYSTONE_REVOKED_KEY_IDS=1`.

Compromise: `POST /revoke {"admin_token": …, "key_id": 1}` — revokes the
id and kills every live session. Persist with `KEYSTONE_REVOKED_KEY_IDS=1`.
A rebuild alone never revokes anything.

Payload secret: new secret, bump `KEYSTONE_PAYLOAD_EPOCH`, reseal, deploy
together.

## Design decisions

- **Envelope signs `session_id`, not the session key.** Key possession is
  proven separately by the request MAC. Two independent bindings.
- **`session_key` lives for the session; the lease is the rotating token.**
  Rotating the HMAC key per heartbeat adds a desync hazard for no gain.
- **Feature grants ride inside the signed manifest.** Per-feature
  single-use tokens are heavier than the threat.
- **Nonces expire with the freshness window, not the grant.** Same
  single-use guarantee, constant memory: ~400 entries per session at the
  rate limit instead of millions over a 30-day grant.
- **Request MACs bind the artifact context at epoch 0.** The client can't
  know the live epoch before the manifest; the epoch does its job in key
  derivation.

## Testing

```sh
cargo test --workspace
```

Covers the writeup's self-test matrix — altered artifacts, expired grants,
wrong-product authorization, reused one-time responses, revoked sessions,
concurrent requests, restart recovery — plus every property in the table
above. One test is `#[cfg(unix)]`.

## License

MIT.
