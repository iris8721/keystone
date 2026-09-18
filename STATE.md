# Keystone — State

## Test-hardening wave (2026-09-12)
- FIXED: `xtask seal` used `format!("{product}:{version}")` as the HKDF
  context while the server derives keys with `artifact_context()` —
  every sealed artifact was undecryptable. Seal now uses
  `keystone_core::artifact_context`; `sealed_blob_decrypts_under_
  server_derived_key` spans the seal↔serve boundary (verified to fail
  on the old code).
- FIXED: `account grant --days 0`/negative wrote a born-dead grant —
  now rejected as an operator error.
- Client replay cache now checks the envelope's own `challenge` field
  (accept_lease_envelope + fetch_manifest), so a verbatim-replayed
  signed envelope is AlreadyConsumed even under a fresh request nonce.
- New tests: at-equality expiry probes (envelope/challenge/lease/
  ConsumedSet), grace-clear probe moved strictly past the old
  deadline, non-vacuous JSON tamper (string-field mutation →
  InvalidSignature), full manifest signed-field sweep, HKDF/MAC
  domain-separation, grace-record 403 on attest+heartbeat, challenge
  burn-on-auth-failure, exchange+revoke rate limits, HWID anomaly
  still-200, heartbeat MAC cross-session 401, expired-grant exchange
  410, malformed payload-auth headers, oversized-artifact 422,
  manifest expiry = min(lease, grant), client replay-cache
  AlreadyConsumed, 410 mapping Active→Expired / Grace→GraceExhausted,
  download hash-mismatch returns no bytes, handoff ttl clamp,
  subject_common_name DER cases, mTLS foreign-CA + expired client
  cert, SPKI-pin-doesn't-mask-SAN, SessionRecord Debug redaction,
  malformed cert_sha256 / corrupt secret_hash backend errors, xtask
  clobber guards.

## Done
- `keystone-core` — signed envelopes (ed25519, domain-separated canonical
  bytes, ms-precision timestamps), challenge nonces, lease/session state
  machine (grace deadline fixed at first failure, Dead is terminal),
  ConsumedSet replay cache, HMAC response MACs, HKDF payload keys,
  EntitlementSource trait, signed manifests + feature grants, sealed
  artifacts + session-bound key wraps (XChaCha20-Poly1305), encrypted
  handoff blobs. 30 tests.
- `keystone-server` — axum service: /challenge /exchange /attest
  /heartbeat /revoke. Server-side challenge book (single-use, TTL),
  session store with sweep, heartbeat kills expired leases AND sessions
  past entitlement expiry, attest+heartbeat require session-key MACs,
  consumed nonces live for the session's whole life (not the rolling
  lease), revoke gated on KEYSTONE_ADMIN_TOKEN, dev seeding behind
  KEYSTONE_DEV_SEED=1, no raw session_ids in logs. 15 tests.
  Payload routes: POST /payload (session-gated signed manifest +
  artifact key wrapped under session-derived material) and
  GET /payload/{product}/{version} (sealed blob, MAC in Authorization
  header). Artifacts stored sealed (XChaCha20-Poly1305, key =
  HKDF(artifact_secret, blob nonce, "{product}:{version}")).
  KEYSTONE_PAYLOAD_DIR + KEYSTONE_PAYLOAD_SECRET[_FILE]; either unset
  = 503. Error codes artifact_not_found/session_not_active/
  artifact_invalid mark transient failures. 14 payload tests.
  Deterrence layer: manifests carry a signed per-release `build_id`
  (seal-time `.build` sidecar, content-hash fallback for pre-sidecar
  artifacts) and both payload routes append pseudonymous JSONL
  download records (HMAC-SHA256 account pseudonym + session tag).
  Local account backend: `accounts.rs` reads KEYSTONE_ACCOUNTS
  (default ./accounts.json), reloads on mtime change, argon2 verify
  with dummy-hash timing parity, expired grants deny, missing/malformed
  file = backend error (503). cert_sha256 pins an account to a client
  cert. Backend selection: accounts file → dev seed → refuse to start.
  8 tests.
- mTLS + SPKI pinning — keystone CA (`xtask ca`), per-account client
  certs (`xtask issue-cert`, CN=account, cert_sha256 recorded on the
  account), server requires client certs when KEYSTONE_CA_CERT is set
  (custom PeerCertAcceptor injects the chain into request extensions),
  /exchange enforces cert_sha256 + CN==account when pinned. Client:
  new_pinned takes CA cert + server SPKI sha256 + optional
  ClientIdentity; SpkiPinVerifier wraps WebPkiServerVerifier — chain
  validation AND leaf-SPKI pin. Live-handshake tests on both sides.
- HWID anomaly flagging — SessionStore::check_fingerprint, per-account
  fingerprint cache, different-hash-inside-10min → warn. Signal, not
  gate. server_time in all signed bodies; client tracks clock_drift.
- `keystone-client` — KeystoneClient SDK: pinned issuer key, https-only
  (new_insecure for dev), cert pinning via new_pinned, 10s timeout,
  heartbeat drives SessionState, 401/404 kill, forged responses enter
  grace, grace deadline clamps heartbeat scheduling, session_key dropped
  on kill + redacted Debug. fetch_manifest/download_payload (unwrap
  artifact key, decrypt, verify-before-return, 256MB cap), per-feature
  grant checks via has_feature (manifest-expiry aware), handoff ttl
  clamped to 5min. 23 tests.
- `xtask` — keygen (issuer seed + pinned pubkey), cert (self-signed dev
  TLS via rcgen), dev (provision + run server), deploy (release build +
  scp to xtask.toml [target]), verify (preflight checklist), seal
  (encrypt a release artifact into the payload dir). Config in
  xtask.toml; `cargo xtask` alias in .cargo/config.toml.
  `account add|grant|revoke|list|cert` manages the accounts file
  (atomic writes, argon2 hashing, cert_sha256 binding via the CA).
- DESIGN.md — spec distilled from PROBE writeup + RSW post-mortem
  threat model.
- Audit fix wave (post dual-review) — heartbeat/attest re-resolve
  entitlements live (grant pulls AND extensions propagate; revocation
  latency = heartbeat interval), /revoke accepts {account} to kill all
  sessions for a user, error JSON carries "code" (bad_challenge is
  401+transient — delayed attests no longer kill sessions), artifact
  plaintext hash cached via .sha256 sidecar (no per-request 256MB
  decrypt), cert check runs after authenticate with uniform 401,
  sliding-window rate limits on exchange/challenge/revoke, artifact
  contexts are length-prefixed (artifact_context), manifests carry
  per-request signed download_id watermarks, client pins SPKI by
  default (new() = pinned; new_unpinned_webpki is the explicit
  downgrade), drift-adjusted time drives all client freshness checks,
  authorize() kills on terminal verdicts and drops the session key,
  handoff sessions are gated until attest succeeds, handoff-in-grace
  clamps the sealed lease to the grace deadline, secret files are
  owner-only (0600/icacls), keygen never prints the seed, account
  secrets prompt instead of argv. 144 tests.

## Env vars
- KEYSTONE_KEYFILE — 32-byte issuer seed file (else ephemeral + warn)
- KEYSTONE_SEED — hex seed alternative
- KEYSTONE_PORT — default 8443
- KEYSTONE_ADMIN_TOKEN — required for /revoke; unset = route closed
- KEYSTONE_DEV_SEED=1 — enables stub dev accounts (dev/devpass, nogrant)
- KEYSTONE_ACCOUNTS — path to the local accounts JSON (default
  ./accounts.json); set-but-missing = refuse to start
- KEYSTONE_PAYLOAD_DIR — directory of sealed {product}-{version}.bin
  blobs; unset = /payload routes closed (503)
- KEYSTONE_PAYLOAD_SECRET / KEYSTONE_PAYLOAD_SECRET_FILE — artifact
  sealing secret (hex / raw 32-byte file); `cargo xtask seal` uses the
  same env to encrypt releases into the payload dir
- KEYSTONE_DOWNLOAD_LOG — JSONL download-record path; default
  `downloads.jsonl` inside the payload dir; no path = logging off
- KEYSTONE_WATERMARK_SECRET — hex HMAC key for account pseudonyms;
  falls back to KEYSTONE_PAYLOAD_SECRET

## In flight
- nothing

## Next
- Forum/xenforo sync is dropped — keystone owns accounts via the local
  file; revisit only if a remote directory is ever needed
- Persistent session store (SQLite) — deliberately skipped; in-memory
  sessions are the more spec-aligned choice (limited, expiring,
  revocable; restart = clean re-exchange)
- Encrypted handoff transport between separate loader/payload processes
  is built; the launch-channel delivery (env/args/shared memory) is the
  integrator's choice

## Open questions
- none blocking. Remaining spec-adjacent items: TPM sealing for client
  certs (spec allows "where available"), binary-level per-download
  watermarking (download_id covers the manifest; re-sealing the binary
  per download is a heavier lift), threaded replay fuzzing beyond the
  8-way heartbeat test.
