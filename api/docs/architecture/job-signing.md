# Signed jobs: the job signer

> Design: [RFC-040 §5.6](../rfcs/RFC-040-platform-sensor-mutual-distrust.md)
> (decision Q11, 2026-10-08). Trust model and remaining gaps:
> [sensor-platform-trust.md](sensor-platform-trust.md). Code:
> `cmd/signer`, `internal/signer` (the signer), `pkg/jobsign` (wire format),
> `internal/infra/signer` (the API's client), `internal/app/command/job_signing.go`
> (claim time).

Anyone who can write the `commands` table, run code in the API process or
sit on the path decides what every sensor scans. Signed jobs move that
authority out of the API: a separate process holds the signing key, checks
each job against its own rules and signs it. A sensor that verifies the
signature runs only what the signer signed.

This page describes what is built: the signer process, the statement and
envelope format, and claim-time signing in the API. Sensor-side
verification is the next sdk-go change; until a sensor verifies, the
envelope protects nothing on that sensor.

## Process boundary

```
 sensor ──claim──▶ API (core) ──POST /v1/jobs/sign──▶ openctem-signer
                     │        (Unix socket, HTTP/1.1)      │
                     │                                     ├─ key file (0400, own volume)
                     ◀────────── DSSE envelope ────────────┤─ state/seq/<sensor-id>
                     │                                     └─ state/signing.log
 sensor ◀── command + signed_job
```

- `openctem-signer` is its own binary (`cmd/signer`, in the API image as
  `/app/openctem-signer`) and runs as its own container and user (uid 1001).
- It imports nothing from the API's application or infrastructure code: no
  database, no Redis, no `APP_ENCRYPTION_KEY`. Its key is never derived from
  an API secret.
- It listens only on a Unix socket (`SIGNER_SOCKET`, mode 0660, owner the
  signer, group the API's). There is no TCP listener; the Compose overlay
  runs it with `network_mode: none`.
- The API never sees the private key. The key volume is mounted into the
  signer container only.

## Key custody (K1)

- Ed25519 private key, PEM PKCS#8, in `SIGNER_KEY_FILE`.
- The signer refuses to start if the file is readable or writable by group
  or others (`chmod 0400` or `0600`).
- `openctem-signer keygen -out <file>` creates a key (mode 0400, never
  overwriting an existing file) and prints its key id and public key.
  `openctem-signer pubkey` prints them again.
- **Key id**: `SHA256:` followed by the lower-case hex SHA-256 of the raw
  32-byte public key (71 characters), for example
  `SHA256:44f86d4295740d2ffe8e20e00c3999440153fb75b4cd2bdbcad3ec42a0eb049d`.
  This is not the 16-hex id of template-signing keys.

## Configuration

Signer (`openctem-signer serve`):

| Variable | Meaning | Default |
|---|---|---|
| `SIGNER_KEY_FILE` | the private key | required |
| `SIGNER_SOCKET` | Unix socket path | required |
| `SIGNER_STATE_DIR` | `seq/` and `signing.log` | required |
| `SIGNER_TENANT_RATE` / `SIGNER_TENANT_BURST` | signing ceiling per organization (token bucket) | 50/s, 500 |
| `SIGNER_SENSOR_RATE` / `SIGNER_SENSOR_BURST` | signing ceiling per sensor | 20/s, 200 |

API:

| Variable | Meaning | Default |
|---|---|---|
| `SIGNER_SOCKET` | the signer's socket. Unset: no signing, claims as before | unset |
| `SIGNER_TIMEOUT` | bound of one call to the signer | 2s |

Compose: `deploy/docker-compose.job-signer.yml` (an opt-in overlay with
setup steps). Helm is not covered yet.

## Signer API

`POST /v1/jobs/sign` with `Content-Type: application/json` and a job
statement (below) without `seq`, `nonce` and `signer`. The answer is `200`
with the envelope, or a refusal:

```json
{"error": "refused", "reason": "bad_expiry", "detail": "..."}
```

| Status | Reasons |
|---|---|
| 400 | `malformed` (not JSON, unknown or mistyped field, trailing data), `bad_kind`, `invalid_id`, `missing_command_type`, `missing_tool`, `bad_payload_digest`, `bad_targets`, `bad_lease_epoch`, `clock_skew`, `bad_expiry`, `server_field_set` |
| 413 | `body_too_large` |
| 429 | `tenant_rate_limited`, `sensor_rate_limited` |
| 500 | `internal` (the sequence number or the signing log could not be written: nothing is signed) |

`GET /v1/keys`:

```json
{"payload_type": "application/vnd.openctem.job.v1+json",
 "keys": [{"keyid": "SHA256:…", "algorithm": "ed25519", "public_key": "<std base64 of 32 bytes>"}]}
```

## What the signer checks

Its own rules; nothing the API sends relaxes them:

- the body is at most 1 MiB, one JSON object, no unknown fields;
- `kind` is `openctem.job/v1`;
- `tenant_id`, `sensor_id` and `command_id` are canonical lower-case UUIDs;
- `command_type` is present (1 to 64 bytes); `tool` is present (an empty
  string for a command that names no tool, at most 128 bytes);
- `payload_sha256` is `sha256:` plus 64 lower-case hex characters;
- `targets` is present (an array, `[]` when there are none), at most 10,000
  entries, each 1 to 1,024 bytes;
- `lease_epoch` ≥ 0;
- `issued_at` within ±2 minutes of the signer's clock;
- `expires_at` after `issued_at` and at most 1 hour after it;
- `seq`, `nonce` and `signer` are not set by the caller;
- the organization's and the sensor's signing ceilings.

It does not yet check targets against an approved scope (see "Not yet").

## Statement

The signer sets `seq`, `nonce` and `signer`, then serializes the statement
**once**. Those bytes are the DSSE payload. A verifier hashes and parses the
payload bytes it received and never re-serializes them.

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `openctem.job/v1` |
| `tenant_id` | UUID | the organization of the command |
| `sensor_id` | UUID | the sensor the claim handed it to |
| `command_id` | UUID | the command |
| `command_type` | string | `scan`, `collect`, `health_check`, `config_update`, … |
| `tool` | string | payload `scanner`, else `preferred_tool`; `""` when neither |
| `payload_sha256` | string | `sha256:` + hex SHA-256 of the command's `payload` JSON value, exactly as the claim response carries it |
| `targets` | string[] | payload `targets` and `target`, trimmed, de-duplicated, in order |
| `lease_epoch` | int | the claim's lease epoch (the command's `lease_epoch`) |
| `issued_at` | RFC 3339 UTC | when the API asked |
| `expires_at` | RFC 3339 UTC | `issued_at` + 1 h, or the command's own expiry if sooner |
| `seq` | uint64 | per sensor, strictly increasing, starts at 1; gaps are possible |
| `nonce` | string | 16 random bytes, base64url without padding |
| `signer` | object | `{"keyid": "SHA256:…"}` |

Example payload (one line on the wire):

```json
{"kind":"openctem.job/v1","tenant_id":"…","sensor_id":"…","command_id":"…","command_type":"scan","tool":"semgrep","payload_sha256":"sha256:…","targets":["."],"lease_epoch":1,"issued_at":"2026-10-09T10:00:00Z","expires_at":"2026-10-09T11:00:00Z","seq":18,"nonce":"o7NeeqW0fElC-531MDwnuw","signer":{"keyid":"SHA256:…"}}
```

## Envelope

[DSSE](https://github.com/secure-systems-lab/dsse) v1:

```json
{"payloadType": "application/vnd.openctem.job.v1+json",
 "payload": "<standard base64 of the statement bytes>",
 "signatures": [{"keyid": "SHA256:…", "sig": "<standard base64 of the 64-byte Ed25519 signature>"}]}
```

The signature is Ed25519 over the pre-authentication encoding:

```
"DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
```

with lengths in ASCII decimal and `payload` the raw statement bytes
(the same PAE as template manifests, `scannertemplate.PreAuthEncoding`).
`jobsign.Verify` is the reference verifier, and `pkg/jobsign/testdata/vector.json`
(key seed, key id, statement bytes, command payload, envelope) is the test
vector a sensor-side verifier must accept, and must refuse once a payload
byte changes.

## On the sensor protocol

- **v2**: every command a claim hands out carries `signed_job` (the
  envelope as a JSON object) on the command object: the claim-N answer of
  `GET /api/v2/sensor/commands` (with the `capacity` feature) and
  `POST /api/v2/sensor/commands/{id}/claim`, including its replay. A listing
  poll and the other transitions never carry it.
- **v3**: `ClaimCommands` and `TransitionCommand` carry the v2 JSON
  (`commands_json`, `command_json`) byte for byte, so the field is the same
  and no proto change is needed.
- **Hello**: the `signed_jobs` feature, and
  `"signed_jobs": {"payload_type": "…", "keys": [{"keyid", "algorithm", "public_key"}]}`
  from the signer's `GET /v1/keys` (cached 5 minutes). `keys` is empty while
  the signer has not answered.
- **The payload digest**: the API writes each signed command's `payload` in
  compact form (what `encoding/json` writes for a raw JSON value, `null`
  when empty) and hashes those bytes. A JSON decoder that keeps the raw
  value (Go `json.RawMessage`) gives the sensor the same bytes; hash them,
  never a re-encoding.

## What a sensor must check (sdk-go, next)

Before it parses anything else of the command:

1. the envelope's `payloadType` is `application/vnd.openctem.job.v1+json`;
2. a signature whose `keyid` is a pinned key verifies over the PAE of the
   payload bytes;
3. `kind` is `openctem.job/v1`;
4. `tenant_id` and `sensor_id` are its own; `command_id` is the command's id;
5. `issued_at` within its clock skew; `expires_at` in the future;
6. `nonce` not seen before (keep nonces until their `expires_at`);
7. `seq` greater than the last accepted one (persisted; gaps allowed);
8. `lease_epoch` equals the command's `lease_epoch`;
9. `payload_sha256` equals the SHA-256 of the received `payload` bytes;
10. it runs `tool` against `targets`, and its local policy agrees.

Any failure: refuse the command (fail it with a refusal), never run it.

## Failure behaviour

- `SIGNER_SOCKET` unset: claims are exactly as before; no envelope, no
  `signed_jobs` feature.
- Signer down, slow (over `SIGNER_TIMEOUT`) or refusing: the command is not
  handed out. A claim-N answer leaves it out; a claim by id answers `503`
  `unavailable` with `Retry-After`. The claim is taken back: the command is
  pending again, still addressed to the sensor only if it was before the
  claim. A claim replay (the sensor already holds the command) is answered
  `503` and the command is left as it is. Claims wait; nothing leaves
  unsigned.
- Each signing is counted in `sensor_job_signing_total{outcome}` with
  `outcome` one of `signed`, `refused`, `unavailable`, and refusals are
  logged with the command and sensor ids.

## State

- `seq/<sensor-id>`: the last sequence number given to the sensor. Each
  number is written to a temporary file, fsync'd, renamed over the file and
  the directory fsync'd **before** the envelope is returned, so a crash can
  skip numbers but never repeat one. A corrupt file stops signing for that
  sensor rather than restarting at 1.
- `signing.log`: append-only JSONL, one line per decision (signed or
  refused) with the time, decision, reason, ids, command type, tool,
  payload digest, target count, `seq`, key id and the SHA-256 of the signed
  statement. Each line carries `prev`, the `sha256:` of the previous line's
  bytes (the first line's `prev` is `sha256:` + 64 zeros), and is fsync'd
  before the answer. A signature whose log line cannot be written is not
  returned. The signer refuses to start on a broken or torn log;
  `openctem-signer verify-log` checks it.

## Not yet (next steps)

- **sdk-go verification** (the list above) and `require_signed_jobs` for
  sensors with a pinned key, then for new enrollments.
- **K3**: the offline root key and the expiring, versioned key set
  (`signers.json`) through which sensors accept online keys, and key
  rotation without re-pinning. Today a sensor pins the online key itself.
- **The signer's ledger and the scope document**: targets checked against
  the organization's approved scope and the zone's ranges, tiers, time
  windows, per-hour distinct-target ceilings; the signed scope document the
  sensor checks next to the job (RFC-040 §5.6 points 4 and 5).
- **Two-person rule for widening** the ledger (RFC-040 P2, then WebAuthn).
- **Template manifests, tool settings and egress policy** signed by the
  signer instead of the API's derived keys (decision Q11).
- **K2** (KMS, Vault Transit, HSM) and a Helm chart for the signer.
- Exporting the signing log to the SIEM and keyed audit checkpoints.
