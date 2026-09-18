# Keystone — Integration Guide

How an operator deploys the server and how a product consumes the
client SDK. Every signature below is verified against the source.

## Operator setup

```bash
cd keystone
cargo xtask ca                     # one-time: private CA (keystone-ca-*.pem)
cargo xtask keygen                 # issuer seed → prints the ed25519 pubkey hex
cargo xtask cert                   # CA-signed server cert → prints server SPKI sha256
cargo xtask payload-secret         # 32-byte artifact sealing secret
cargo xtask account add alice      # prompts for the secret (hidden input)
cargo xtask account grant alice --product aimbot --days 30 --features esp,aimbot
cargo xtask issue-cert alice       # mTLS client cert (CN=alice) → prints cert sha256
cargo xtask seal --product aimbot --version 1.0.0 --in aimbot.bin --out payloads/
```

Server env:

```
KEYSTONE_KEYFILE=keystone.key
KEYSTONE_TLS_CERT=keystone-cert.pem
KEYSTONE_TLS_KEY=keystone-key.pem
KEYSTONE_CA_CERT=keystone-ca-cert.pem      # enables mTLS requirement
KEYSTONE_ACCOUNTS=accounts.json
KEYSTONE_PAYLOAD_DIR=payloads/
KEYSTONE_PAYLOAD_SECRET_FILE=payload.secret
KEYSTONE_ADMIN_TOKEN=<random>              # enables /revoke
KEYSTONE_DOWNLOAD_LOG=downloads.jsonl      # optional watermark log
KEYSTONE_PORT=8443
```

`cargo xtask dev` provisions all of this for local testing.

## The loader (client-facing binary)

Bake in: issuer pubkey (from `keygen`), CA cert PEM, server SPKI pin,
and the user's client cert/key pair.

```rust
let client = KeystoneClient::new(
    "https://key.example.com",
    issuer_pubkey,          // ed25519 VerifyingKey — the ONLY trusted issuer
    ca_cert_pem,            // keystone CA — the ONLY trusted root
    server_spki_sha256,     // leaf SPKI pin — survives cert rotation on same key
    Some(client_identity),  // ClientIdentity { cert_pem, key_pem }
)?;

let mut session = client
    .exchange("alice", &secret, "aimbot", hwid)
    .await?;
```

`new` is the pinned constructor — SPKI + private CA + optional mTLS
identity. `new_unpinned_webpki` exists but trusts public roots (don't).
`new_insecure` permits http for tests (never ship).

## The handoff (loader → payload)

```rust
let (blob, handoff_key) =
    session.make_handoff("aimbot.exe", Duration::minutes(2))?;
// deliver blob + handoff_key through the launch channel:
// env var, argv, shared memory — the transport is your choice.
// ttl is clamped to 5 minutes; a grace-period handoff clamps the
// sealed lease to the grace deadline.
```

## The payload (protected product)

```rust
// opens the AEAD blob — never saw credentials
let mut session =
    ClientSession::from_handoff(&handoff_key, &blob, "aimbot.exe", Utc::now())?;

// REQUIRED: independent attestation. authorize() returns
// NotAuthenticated until this succeeds — step 6 is unskippable.
let lease = client.attest(&mut session, "aimbot.exe").await?;

// session-gated payload: manifest + wrapped artifact key
let (manifest, artifact_key) =
    client.fetch_manifest(&mut session, "aimbot", "1.0.0").await?;

// downloads the sealed blob, decrypts, sha256-verifies against the
// signed manifest — returns plaintext or nothing
let bytes = client
    .download_payload(&mut session, "aimbot", "1.0.0")
    .await?;

// runtime feature gates — manifest-expiry aware
if session.has_feature(&manifest.manifest, "esp", Utc::now()) {
    // feature is granted AND the manifest hasn't outlived its lease
}
```

## The keepalive loop

```rust
loop {
    session.authorize()?;        // no args — uses drift-adjusted time;
                                 // kills itself + drops the key on
                                 // terminal verdicts
    if let Some(due) = session.next_heartbeat_due(Utc::now()) {
        if due <= Utc::now() {
            match client.heartbeat(&mut session).await {
                Ok(_lease) => {}
                Err(_) if !session.is_alive() => break,  // dead is final
                Err(_) => {}                             // transient → grace
            }
        }
    }
    // ... protected work — call authorize() at every gate ...
}
```

Heartbeat semantics: transport failure / `bad_challenge` /
`artifact_not_found` / `rate_limited` → grace (fixed deadline, retries
never extend). 401/403/404/410 verdicts → session killed immediately.
A forged or unverifiable response → grace (treated as never arrived).

## What an attacker faces

| Attack | Result |
|---|---|
| hosts-file redirect / rogue CA | dead — SPKI pin + private CA + mTLS |
| captured responses replayed | dead — challenge-bound, single-use, consumed nonces outlive lease renewals |
| captured sealed payload | dead — artifact key unwraps only with live session material |
| revoked subscription | dead within one heartbeat — live re-resolution |
| leaked build | attributable — per-request signed download_id + pseudonymous log |
| patched client binary | still needs server-held secrets every lease window |
| delayed/dropped attest | transient, not fatal — bad_challenge burns grace, not the session |

## Integrator checklist

- [ ] issuer pubkey + CA cert + SPKI pin baked into the client build
- [ ] per-user client certs distributed with accounts
- [ ] handoff transport chosen (env/argv/shared memory)
- [ ] `authorize()` called at every protected operation, not just startup
- [ ] `has_feature` gates on every premium feature path
- [ ] heartbeat loop running for the process lifetime
- [ ] no secrets in the shipped binary — only pubkey, CA cert, SPKI pin
