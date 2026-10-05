# Agent Identity & Credentials

> Design of record: [RFC-014](../rfcs/RFC-014-agent-identity.md).
> This document tracks **what is shipped vs planned** for how our agents
> authenticate. It does **not** cover external connectors (DefectDojo / Jira /
> Nessus) — those keep the per-tenant AES-encrypted credential + webhook-HMAC
> model, a different threat model (we hold *their* secret; we cannot impose our
> identity on a third-party SaaS).

## Model in one paragraph

Every agent has its **own identity** — one `agents` row with an inline
`api_key_hash` (HMAC-SHA256 + server pepper of an `octs_` key with 32 random
bytes, shown once at issue; see *Credential formats*; older sensors may still
hold a legacy `rda_` key). This is deliberately **not** a shared account: one
leaked key revokes/audits independently, unlike a single tenant-wide token. On
top of that identity the credential is evolving from a *static* secret toward a
**short-lived, auto-rotating** one, so a
leaked key self-revokes at its next renewal instead of living forever.

## Lifecycle

```
ENROLL   registration token (ExpiresAt / MaxUses / DefaultScopes)   [shipped]
   │       → mints a per-agent identity + first API key
ISSUE    api_key_hash + api_key_prefix, optional key_expires_at     [shipped]
RUN      auth = peppered-hash lookup
         → Status.CanAuthenticate()  (active / disabled / revoked)
         → NOT expired (key_expires_at)                             [shipped 1b]
RENEW    agent POSTs /api/v1/agent/renew with its current key       [shipped 1a]
         → fresh key (+ fresh expiry when a TTL is configured)
ROTATE   admin POST /agents/{id}/regenerate-key (hard, tenant)      [shipped]
REVOKE   Status = revoked  → auth short-circuits immediately        [shipped]
         short key TTL      → implicit revocation (no CRL)           [shipped 1b]
```

## What is shipped

| Capability | Where | Notes |
|-----------|-------|-------|
| Per-agent identity + peppered hash | `internal/app/agent/service.go` (`generateAgentAPIKey`, `AuthenticateByAPIKey`) | `crypto.HashTokenPeppered`; legacy plain-SHA256 fallback for pre-pepper rows |
| Enrollment tokens (short-lived, use-limited, scoped) | `pkg/domain/agent/registration_token.go` | the k8s bootstrap-token analog |
| Admin hard rotation | `POST /agents/{id}/regenerate-key` (JWT, `AgentsWrite`) | old key dies immediately; tenant-scoped |
| **Agent self-renew** (Phase 1a) | `POST /api/v1/agent/renew` (agent API-key auth) → `AgentService.RenewAPIKey` | agent rotates its **own** key; works for tenant **and** platform agents; TOCTOU-safe (re-reads status by id) |
| **Key expiry** (Phase 1b) | `agents.key_expires_at` (migration `000185`), `Agent.IsKeyExpired()`, enforced in `AuthenticateByAPIKey` | **NULL = never expires** (default + all legacy rows) |
| Configurable key TTL | `AGENT_KEY_TTL` env → `AgentService.SetKeyTTL` | **default `0` = disabled**; only self-renew honors it |
| **Rotation overlap** (Phase 3) | `AgentAPIKeyRepository` over the `agent_api_keys` table; auth accepts the inline key **or** an active/valid key row | self-renew under a TTL issues the new key as a row; the key the sensor renewed **with** (inline or row) and every other key it still held stop after `SENSOR_KEY_RENEW_GRACE` (default 15 min), so a renewal leaves one long-lived key (see *Renewal retires the presented key*); per-key `use_count`/`last_used` audit |
| Agent auto-renew (Phase 2, SDK) | `sdk-go` `KeyRenewManager` + agent `-key-autorenew` flag | renews at ~½ TTL, swaps both clients, persists to the creds file; *pending the sdk-go v0.5.0 release |

### Renewal retires the presented key

A renewal has exactly one successor. Authentication records which credential
the sensor presented (`SensorIdentity.KeyID`: a `sensor_api_keys` row, or nil
for the inline key on the sensor row), and both renew routes
(`POST /api/v1/agent/renew`, `POST /api/v2/sensor/keys`) pass that identity to
`RenewAPIKey`. It issues the new key and, in the same transaction:

- caps `expires_at` of every other active key row of the sensor at
  now + `SENSOR_KEY_RENEW_GRACE`;
- caps the inline key's `key_expires_at` the same way, guarded by the hash
  that was presented (or read), so an admin regeneration landing in between is
  not cut short.

That transaction (`SensorAPIKeyRepository.RotateKey`) first locks the sensor
row (`SELECT … FOR NO KEY UPDATE`), so renewals of one sensor run one after
another and the last one holds the only long-lived key. Done as separate
writes, concurrent renewals interleaved: each retired only the keys that
existed when it ran, and a superseded key could stay valid until its own
expiry. The lock is a row lock released with the transaction, never a
session advisory lock on a pooled connection.

The retirements only bring an expiry earlier, never extend one, and touch
nothing but the expiry columns, so a concurrent admin revoke or regeneration is
not undone. A failure rolls the whole renewal back (the sensor keeps its old
key and retries). Without a TTL the renewal replaces the inline key at once and
caps any key rows the same way, under the same lock
(`SensorAPIKeyRepository.ReplaceInlineKey`).

The admin hard rotation takes the same lock. `RegenerateAPIKey` installs the
new inline key and revokes every key row in one transaction
(`SensorAPIKeyRepository.RegenerateKey`). Before writing anything, a renewal
re-checks under the lock that its authentication still holds:

- the sensor is still `active` (refused with 403 otherwise);
- the presented credential is still valid: the presented key row is still the
  sensor's, active, unrevoked and unexpired, or the sensor's inline hash is
  still the presented key's and unexpired (refused with 401 otherwise).

A refused renewal writes nothing and is audited as
`sensor.key_renewal_refused` (severity high). Without the re-check, a renewal
that authenticated with the old key just before a regeneration could mint its
row after the regeneration had revoked the rows, and a key the administrator
killed (after a suspected leak, say) was renewed into a valid one. Now a
renewal racing a regeneration either commits first, and the regeneration
revokes its key, or runs after it and is refused. Either way the regenerated
key is the only valid credential.

What this buys: a copied `rda_` key can no longer renew itself a parallel line
of long-lived keys. Whoever renews last holds the only long-lived key, and the
other holder is locked out after the grace and has to be re-enrolled, which an
administrator sees. Two concurrent renewals with the same key also end with one
long-lived key: "older than the new row" means the newer row is never capped by
the older renewal. `SENSOR_KEY_RENEW_GRACE=0` retires the presented key at once
(in-flight requests made with it then fail).

### Enabling short-lived credentials (`AGENT_KEY_TTL`)

Set e.g. `AGENT_KEY_TTL=24h`. Then every call to `/api/v1/agent/renew` issues a
key that expires in 24h, and the renew response includes `expires_at` so the
agent can schedule its next renewal. With the variable **unset (the default),
renewed keys never expire** and behavior is identical to before Phase 1b.

> **Operational prerequisite.** Do **not** enable a TTL until agents actually
> auto-renew (Phase 2). A configured TTL only sets expiry *on renewal*, and an
> agent that never renews would simply keep its non-expiring key — but an agent
> that renews once and then stops would lock itself out at expiry. Treat TTL as
> off until the daemon renew loop ships.

## What is planned (not yet shipped)

| Phase | Capability | Scope |
|-------|-----------|-------|
| **4** | Scope enforcement (`RunnerScopes` / `SensorScopes`) at the authz layer | least-privilege, like k8s NodeRestriction; rides on the Phase-3 multi-key (rotated keys already carry per-type scopes) |
| **5** | OIDC federation for ephemeral CI runners — exchange the CI provider's OIDC token for a short-lived scoped agent token | zero stored secret; strongest option for CI |

## Credential formats

Owner decision 2026-10-03 (RFC-032 revision, §10.4). Every key issued since
then (create, admin regeneration, self-renewal, the overlapping `RotateKey`
path) is an `octs_` key; `rda_` keys are no longer issued.

| Prefix | What | Shape | Total length | Status |
|---|---|---|---|---|
| `octs_` | sensor API key | `octs_` + 43 base62 (32 random bytes, zero-padded) + 6 base62 (CRC32 of the random part) | 54 | issued |
| `octe_` | one-time sensor enrollment token (RFC-032 §6.2) | same shape as `octs_` | 54 | reserved; not issued yet |
| `rda_` | legacy sensor API key | `rda_` + 64 lower-case hex, no checksum | 68 | accepted until the sunset |

Base62 alphabet: `0-9A-Za-z`. The checksum is `CRC32-IEEE(random part)` as an
unsigned 32-bit integer written in base62 and left-padded with `0` to 6
characters. Code: `pkg/sensorkey` (`New`, `Valid`, `IsLegacy`,
`AcceptableSensorKey`, `DisplayPrefix`).

- **No sensor prefix starts with `oct_`.** The HTTP layer routes `oct_` bearer
  tokens to user / MCP API-key authentication
  (`internal/infra/http/middleware/apikey_auth.go`); `octs_` and `octe_` share
  the letters but not the underscore position. Pinned by
  `middleware/apikey_sensor_prefix_test.go` and
  `pkg/sensorkey/sensorkey_test.go`.
- **The checksum is not a security control.** Anyone can compute a CRC32. It
  only lets a secret scanner match with near-zero false positives and lets the
  API turn away a mistyped or truncated key without a database lookup. The
  key's security is its 256 random bits and the peppered hash.
- **Authentication** runs `AcceptableSensorKey` first: an `octs_` key with a bad
  length, alphabet or checksum, and any `octe_` token, get the same generic
  401 as an unknown key with no hashing or lookup. Everything else (legacy
  `rda_` keys) goes on to the peppered-hash lookup unchanged.
- **Display prefix.** `api_key_prefix` / `sensor_api_keys.key_prefix`
  (`VARCHAR(12)`) store the first 10 characters (`octs_` + 5 random, about 30
  bits, no more than the 8 hex characters an `rda_` prefix showed). The SDK
  logs at most 8 characters of a key (`APIKeyHint`), a prefix of the display
  prefix, so an operator can match a log line to the Sensors page. Full keys
  are never logged and never written to the audit log.
- **Legacy `rda_` keys** keep authenticating until the sunset: **90 days after
  RFC-032 enrollment and Ed25519 key-bound identity ship** (this replaces the
  earlier 2027-04-01 date). A sensor moves to `octs_` on its next renewal
  (`RenewAPIKey`, the sensor renews its own key before expiry); an admin can also regenerate the
  key. `Sensor.IsLegacyKey()` is true while the sensor's effective key
  (`KeyState`) is `rda_`; the sensor response carries `legacy_key` and the
  Sensors page tags those sensors ("legacy key"). The renewal that moves a
  sensor off `rda_` is recorded in the `sensor.key_renewed` audit event with
  `previous_key_format: "rda"`, `key_format: "octs"` and
  `upgraded_from_legacy_key: true` (format names only, no key material). The
  gauge **`openctem_sensor_legacy_keys`** (set by the sensor health checker on
  each pass, logged when it changes) counts non-revoked sensors still on
  `rda_`; it has to reach zero before the sunset.

### Scanning for leaked OpenCTEM credentials

The repository's `.betterleaks.toml` carries these rules; customers can add
the same patterns to their own scanners (gitleaks / betterleaks, GitHub
secret scanning custom patterns, TruffleHog, a SIEM):

| Pattern name | Regular expression | Keyword |
|---|---|---|
| OpenCTEM sensor API key | `\bocts_[0-9A-Za-z]{43}[0-9A-Za-z]{6}\b` | `octs_` |
| OpenCTEM enrollment token | `\bocte_[0-9A-Za-z]{43}[0-9A-Za-z]{6}\b` | `octe_` |
| OpenCTEM legacy sensor key | `\brda_[0-9a-f]{64}\b` | `rda_` |

```toml
# gitleaks / betterleaks
[[rules]]
id = "openctem-sensor-key"
description = "OpenCTEM sensor API key (octs_)"
regex = '''\b(octs_[0-9A-Za-z]{43}[0-9A-Za-z]{6})\b'''
secretGroup = 1
keywords = ["octs_"]
```

For GitHub secret scanning custom patterns use the expression without `\b`
as *Secret format* and `(?:\A|[^0-9A-Za-z_])` / `(?:\z|[^0-9A-Za-z_])` as
*Before* / *After secret*. A scanner that can run code should also verify the
checksum to drop look-alikes:

```python
import zlib
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def b62(n, width):
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = ALPHABET[r] + out
    return out.rjust(width, "0")

def is_openctem_token(tok):
    body = tok[5:]
    return (tok[:5] in ("octs_", "octe_") and len(body) == 49
            and b62(zlib.crc32(body[:43].encode()), 6) == body[43:])
```

A leaked key is revoked by regenerating it on the Sensors page (or revoking
the sensor); OpenCTEM is self-hosted, so a report goes to the installation's
administrator, not to the vendor.

## Why not a shared account token

A single tenant-wide (or global) token is rejected: one
leak compromises **every** agent, with no per-agent revoke, no per-agent audit,
and no way to scope one runner differently from another. Per-machine identity +
short-lived rotating credential bounds the blast radius of one leak to one
machine and one renewal window. OpenCTEM was already on that axis; Phases 1a–1b close the "static key that never expires" gap.
