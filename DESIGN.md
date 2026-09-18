# Keystone — Design

Source: PROBE forum writeup "Authentication For Dummies" (Sep 4, 2026).
Server-authoritative auth for paid software. The server decides what is
allowed; authorization is limited, revocable, and bound to each operation.

## Actors

- **Client** — entry point, not authority. Collects credentials, HWID,
  telemetry. Talks to the server.
- **Application** — the protected product. Never trusts "the client already
  checked." Performs its own exchange before enabling anything.
- **Server** — sole authority. Sessions, entitlements, expiry, revocation,
  replay rejection. All checks live here, not in shipped code.

## Session flow

1. Client opens, collects credentials + HWID + telemetry.
2. Client → Server: authorization exchange.
3. Server validates credentials AND entitlement for the requested product.
   Authentication = who. Authorization = what they're allowed.
4. On success: limited, expiring session. A license key never becomes a
   permanent bearer token.
5. Client → Application: encrypted handoff. Minimal sensitive material —
   no credentials, logs, or temp files. App validates process identity.
6. Application → Server: independent attestation. Its own exchange, its
   own proof.
7. Server → Application: authorization lease. App enables only after all
   checks pass.
8. Loop while authorized: signed heartbeat → lease refresh. A heartbeat is
   not a connectivity check — a reachable server can still reject.
9. Explicit rejection ends access. Network failure gets a bounded grace
   period; retries never extend it. Grace exhausted → stop protected
   operations, clear session material.

## Request integrity (replay model)

Every authorization response must be:

- **Signed** by a trusted issuer (server holds the private key; builds
  ship only the public verification key).
- **Fresh** — bound to a challenge/nonce the verifier issued.
- **Scoped** — bound to session, audience, and the requested operation.
- **Single-use** — accepted once, then marked consumed.

Rejection cases: altered response (bad signature), replayed old response
(challenge mismatch), replayed accepted response (already consumed),
expired, wrong product, revoked session.

## Payload rules

- Payload does its own auth — never trusts a loader's boolean.
- Download permission ≠ runtime permission. Session-gate payloads; bind
  product, version, artifacts, authenticated manifests.
- Signed builds, verified before launch. Bind release info.
- No secrets in distributed builds. Ever. No signing keys, admin creds,
  master keys, raw webhooks, env secrets. Valuable operations stay
  server-side; a product that works fully offline isn't protected.
- Pseudonymous build identifiers + download records for leak
  investigation. Watermarks are supporting evidence, not proof.

## Key compromise model

If a private key leaks in a build: revoke the key AND invalidate affected
sessions. Rebuilding without the secret is not enough — the old key stays
trusted until revoked. Revocation limits future abuse; it doesn't undo
earlier access.

## Self-test matrix

Verify rejection of: altered artifacts, expired grants, wrong-product
authorization, reused one-time responses, revoked sessions. Also:
concurrent requests, restart recovery, normal operation.

## Crate mapping

- `keystone-core` — session/lease/challenge types, signing, replay cache,
  entitlement model, error taxonomy.
- `keystone-server` — exchange, attest, heartbeat, revoke endpoints;
  session store; entitlement source (forum group sync).
- `keystone-client` — challenge request, handoff encode/decode, heartbeat
  loop with bounded grace, consumed-response tracking.

## Threat model — RSW post-mortem

RSW failed because its C2 was a delivery mechanism, not a control
mechanism: once bootstrapped, the cheat ran fully offline. Every failure
below is a keystone requirement.

Observed failures → keystone countermeasures:

- No cert pinning (hosts file + self-signed mock accepted) → SPKI pin in
  client; pinning alone is patchable, so it must pair with signed
  envelopes — patching the pin still yields no valid signatures.
- Deterministic responses replay forever → every response signed over
  session key + client nonce + body; captures are worthless.
- Single-byte ban check, fake config acks, static login JSON, integer
  token → all server state is signed structs with nonces, server-minted
  IDs, short-lived rotating tokens, server_time for drift checks.
- Hardcoded symmetric payload key → payload keys derived via
  HKDF(license_secret || session_pubkey || epoch); static extraction
  yields nothing.
- No HWID binding → HWID is an anomaly signal, not identity (facade
  exists; assume spoofable). Flag same-account/different-fingerprint
  within short windows; never a hard gate.
- No mTLS → per-user client certs, TPM-sealed where available. Still
  extractable under instrumentation — a cost-raiser, not a wall.
- Cheat phones home never after bootstrap → signed keepalive leases;
  protected ops require fresh grants.
- One endpoint for upload + fetch → distinct routes, distinct auth
  requirements.
- No payload integrity → signed manifests {sha256, version,
  feature_grants} verified before execution.
- No local feature gating → server-issued per-feature grant tokens the
  payload consumes at runtime.
- Loader trusts system DNS → pinned endpoints, no hosts-file trust.

The hard truth: every client-side check is one patch from dead. The only
defense that survives patching is the server holding something the
client needs and cannot forge — session keys, fresh grants, operations
that cannot complete offline. Defense-in-depth means many independent
checks so each bypass is separate work, with the load-bearing checks
server-side where no patch reaches.

Deterrence layer: individualized build watermarks make leaked builds
attributable. Doesn't stop the crack — changes what happens to the
leaker after.
