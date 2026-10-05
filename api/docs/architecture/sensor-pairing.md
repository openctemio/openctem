# Sensor pairing, key-bound identity and grants

Design and decisions: [RFC-052](../rfcs/RFC-052-sensor-pairing-and-authorization.md).
Operator steps: [how-to: pair a sensor](../how-to/pair-a-sensor.md).
Trust boundaries and the remaining gaps: [sensor-platform-trust.md](sensor-platform-trust.md).

This page is the map of the code: where each part lives, what it checks and
which tests pin it. Status per part is in the table at the end.

## Identity: one key per sensor, every request signed

A paired sensor holds an Ed25519 private key that never leaves its host. The
platform stores the public key in `sensor_keys` (one row per key, `pending`
until the sensor confirms its pairing, then `active`, `revoked` on re-pair or
revocation). Every request carries an RFC 9421 signature in the narrow profile
of RFC-052 §4.3:

| Piece | api | sdk-go |
|---|---|---|
| Profile (parse, signature base, verify, sign) | `pkg/sensorsig` | `pkg/sensorsig` (identical rules; shared vectors) |
| Verifier on the sensor routes | `internal/infra/http/handler/sensor_signature.go`, called by v1 `AuthenticateSource` and v2 `Authenticate` before the bearer path | — |
| Key lookup, status, sensor status | `SensorService.AuthenticateSigned` (`internal/app/sensor/keybound.go`) | — |
| Nonce store | Redis `SET NX` per keyid and nonce, TTL = window + skew; per-replica fallback | — |
| Signer on every request | — | `sensorsig.Transport` wrapping the API client's transport; removes any bearer header |

Order on a request: parse the headers (anything outside the profile is `401`
at once) → window → key by `keyid` (active key, active sensor) → signature →
nonce → body against `Content-Digest`. The body is read only after the
signature verified, so an unauthenticated caller cannot make the API buffer
it.

## Pairing

| Piece | Where |
|---|---|
| Wire types, SAS, commitment, transcripts, codes | `pkg/sensorproto/pairing` (api and sdk-go; `testdata/vectors.json` byte-identical) |
| Service: start, reveal, poll, confirm, lookup, expectations, approve, deny | `internal/app/sensorpairing` |
| Platform pairing key | HKDF-SHA256 of `APP_ENCRYPTION_KEY`, info `openctem/sensor-pairing/platform-key/v1` (Ed25519 seed) |
| Code storage | HMAC-SHA256 with the sensor-key pepper (`SENSOR_KEY_PEPPER`), never in clear |
| Repository | `internal/infra/postgres/sensor_pairing_repository.go` (`sensor_pairings`) |
| Sensor-plane routes | `internal/infra/http/routes/sensor_pairing.go`: `/api/v2/sensor/pairings*`, own group (documented in `api/openapi/sensor-protocol-v2.yaml`), signed by the pairing key, rate-limited |
| User-plane routes | `/api/v1/sensor-pairings/*` (`sensors:pair`, `sensors:approve`); `lookup`, `expectations`, `{id}/approve`, `{id}/reject` |
| Step-up | `AuthService.VerifyStepUp` (`internal/app/auth/stepup.go`): TOTP if enrolled, else password, else a session younger than 10 minutes |
| Sensor side | `sdk-go/pkg/sensorkit` (`Pair`, identity store, auto-pair), `sensor` (`openctemio-sensor pair`) |

States of a pairing row:

```
pending ──nonce──▶ pending (sas set) ──approve──▶ approved ──complete──▶ completed
   │                     │                            │
   └──────expiry────────┴──────reject──▶ denied       └──10 min──▶ expired (key revoked)
```

Reverse mode starts as an `expecting` row with a tenant and a code but no
key; the sensor's start request fills in the key and turns it `pending`.

## Grants

| Piece | Where |
|---|---|
| Model, profiles, narrowing comparison, effective grant | `pkg/domain/sensor/grant.go` |
| Command tier | `pkg/domain/sensor/grant_tier.go` (stage catalog tier of the tool; custom templates and callbacks raise to T2; unknown tool T2) |
| Repository | `internal/infra/postgres/sensor_grant_repository.go` (`sensor_grants`) |
| Claim gate | `internal/app/command/local_policy.go` `dispatchGate.refusal` (poll, claim-N, claim by id) |
| Push ingest | `internal/app/ingest/quarantine.go` `admitUnsolicited` (grant first, then role and tenant policy) |
| Remote actions | heartbeat answers filter gated actions (`internal/app/sensor/doorbell.go`) |
| Management API | `GET/PUT /api/v1/sensors/{id}/grant`, `POST /api/v1/sensors/{id}/trust`, `GET /api/v1/sensor-grant-profiles` |

## Audit and timeline

Every event below is an audit entry and a sensor timeline event; the ones
marked ✉ notify every administrator of the organization in the app.

| Event | Severity |
|---|---|
| `sensor.pairing_approved` ✉ | high |
| `sensor.pairing_denied` | medium |
| `sensor.pairing_completed` | medium |
| `sensor.repaired` ✉ | high |
| `sensor.key_revoked` | high |
| `sensor.grant_narrowed` | medium |
| `sensor.grant_widened` ✉ | high |
| `sensor.trust_changed` ✉ (promotion) | high |
| `sensor.claim_refused_grant` | medium |
| `sensor.credential_refused` | high |
| `sensor.push_refused_grant` | medium |
| `sensor.identity_policy_changed` ✉ | high |

## Status

| Part | Status |
|---|---|
| RFC, docs | this PR series |
| Key-bound identity (verifier, `sensor_keys`) | in implementation (SP1b) |
| Pairing API, step-up, identity policy | in implementation (SP1c) |
| Grants and enforcement | in implementation (SP2a) |
| SDK signer, pairing client, CA pin | in implementation (SP1d) |
| Sensor `pair` command, auto-pair | in implementation (SP1e) |
| Console | in implementation (SP1f/SP2b) |
| Trust Restricted/Quarantined, signals, kill switch | planned (SP3) |
| Two-person widening, time-boxed grants, purge-by-sensor | planned (SP4) |
