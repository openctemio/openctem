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
envelope format, claim-time signing in the API, and the key set signed by
an offline root through which sensors accept signer keys. Sensors verify
with sdk-go (`pkg/jobsig`); until a sensor verifies, the envelope protects
nothing on that sensor.

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
| `SIGNER_KEYSET_FILE` | the key set signed by the offline root, served at `GET /v1/keyset`; read at start and on `SIGHUP` (see "Key sets and the offline root") | unset: no key set |
| `SIGNER_TENANT_RATE` / `SIGNER_TENANT_BURST` | signing ceiling per organization (token bucket) | 50/s, 500 |
| `SIGNER_SENSOR_RATE` / `SIGNER_SENSOR_BURST` | signing ceiling per sensor | 20/s, 200 |

API:

| Variable | Meaning | Default |
|---|---|---|
| `SIGNER_SOCKET` | the signer's socket. Unset: no signing, claims as before | unset |
| `SIGNER_TIMEOUT` | bound of one call to the signer | 2s |

Compose: `deploy/docker-compose.job-signer.yml` (an opt-in overlay with
setup steps). Helm is not covered yet.

## Key sets and the offline root (K3)

A sensor that pins one online key must be paired again to change it. With
a key set it pins the installation's **root** key instead, and accepts job
signatures from the online keys the current key set lists. Rotating or
revoking an online key is then a new key set, and a stolen online key is
useful only until it is dropped from the key set or the key set expires.

**The root key never lives on the platform host.** It is an Ed25519 key
created and kept offline (an air-gapped machine, a hardware token holding
the file, a safe); it signs only key sets. The signer, the API and the
database never see it. The signer checks the key set it is given, but it is
not the trust anchor: the sensor's pin is.

### Format

A DSSE envelope, payload type `application/vnd.openctem.keyset.v1+json`,
Ed25519 over the PAE of the exact payload bytes (as for jobs), with one
signature whose `keyid` is the root's. The payload (one line on the wire):

```json
{"kind":"openctem.keyset/v1","version":3,"issued_at":"2026-10-09T10:00:00Z","not_after":"2026-11-08T10:00:00Z",
 "keys":[{"keyid":"SHA256:…","algorithm":"ed25519","public_key":"<std base64 of 32 bytes>"}],
 "root_keyid":"SHA256:…","root_public_key":"<std base64 of 32 bytes>"}
```

| Field | Rule |
|---|---|
| `kind` | `openctem.keyset/v1` |
| `version` | integer ≥ 1, strictly increasing across the key sets of one root |
| `issued_at`, `not_after` | RFC 3339 UTC; `not_after` after `issued_at` and at most 30 days later |
| `keys` | 1 to 16 online keys, as `GET /v1/keys` lists them; each `keyid` is its key's own; no duplicates; never the root |
| `root_keyid` | the id of the root key (what a sensor pins) |
| `root_public_key` | the root's raw key, whose recomputed id must be `root_keyid`, so a sensor that pinned only the id can check the signature |

A verifier (`jobsign.VerifyKeySet` is the reference, and sdk-go's
`jobsig` follows the same rules) checks, in order: the envelope is at most
64 KiB and its payload type is the key set's; the payload decodes with no
unknown field and no trailing data; the fields above; a signature by
`root_public_key` verifies; `root_keyid` is the **pinned** root;
`issued_at` is at most 2 minutes ahead of its clock; `not_after` is later
than its clock minus 2 minutes. A sensor then keeps the highest version it
accepted (on disk): a lower version is refused (rollback), and the same
version is accepted only with the same bytes. A job is accepted only from
a key the current key set lists (or a key pinned explicitly on the
sensor).

Test vectors: `pkg/jobsign/testdata/keyset_vector.json` (root seed, keys
`A` and `B`, key sets 1 `[A]`, 2 `[A, B]`, 3 `[B]`, and one signed by
another root). Key `A` is the key of `testdata/vector.json`, so that
signed job verifies under key sets 1 and 2 and is refused under 3.

### Ceremony

On the offline machine, with the `openctem-signer` binary (the API image
carries it as `/app/openctem-signer`):

1. **Root, once:** `openctem-signer root keygen -out root.key` writes the
   key (0400) and prints `root keyid: SHA256:…`. Back the file up offline.
   Give the keyid to whoever installs sensors: they pin it with
   `SENSOR_JOB_SIGNING_ROOT=SHA256:…` (strongest), or a sensor pins the
   root of the first key set it sees when it pairs.
2. **First key set:** on the platform host, `openctem-signer pubkey`
   prints the online key's `public_key`. Offline:
   `openctem-signer keyset sign -root root.key -version 1 -days 30 -key <public_key> -out keyset-1.json`.
   `-key` takes the base64 key or a PEM key file and repeats for each key.
3. **Deploy:** copy the key set (it is public) to the signer's
   `SIGNER_KEYSET_FILE` and restart the signer or send it `SIGHUP`. The
   signer refuses a key set that is not signed by its root, has expired,
   does not list the signer's own key, or is a lower version (or the same
   version with other bytes) than the one it serves; on `SIGHUP` it then
   keeps the current one and logs the error. `openctem-signer keyset show
   -root SHA256:… keyset-1.json` checks a file as a sensor would.
4. **Renew** before `not_after` (the signer warns from 7 days before, and
   logs an error once it has expired): sign the same keys with the next
   version. An expired key set makes sensors that pin the root refuse every
   job until a new one is deployed (fail closed).
5. **Rotate an online key:** create the new key
   (`openctem-signer keygen -out signer-2.pem`); sign version N+1 listing
   the old and the new key; deploy it to the running signer; switch the
   signer to the new key (`SIGNER_KEY_FILE`) with the N+1 key set and
   restart it; once every sensor has seen N+1, sign N+2 without the old
   key. No sensor is paired again.
6. **Revoke a key** (stolen or retired): sign the next version without it
   and deploy it. Sensors refuse jobs signed by it from the moment they
   accept that version; a sensor that does not see it still refuses at the
   old version's `not_after`.

The API fetches the key set from the signer (`GET /v1/keyset`, cached 5
minutes, passed on only when it is signed by the root it names) and
carries it in hello as `signed_jobs.keyset`. A change of key set changes
the doorbell's `config_version`, so sensors re-read hello.

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

`GET /v1/keyset`: the key set envelope exactly as deployed, or `404`
`{"error": "no_keyset"}` when `SIGNER_KEYSET_FILE` is not set.

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
  the signer has not answered. `"keyset"` carries the key set envelope (a
  JSON object) when the signer serves one; a new key set changes the
  doorbell's `config_version`.
- **The payload digest**: the API writes each signed command's `payload` in
  compact form (what `encoding/json` writes for a raw JSON value, `null`
  when empty) and hashes those bytes. A JSON decoder that keeps the raw
  value (Go `json.RawMessage`) gives the sensor the same bytes; hash them,
  never a re-encoding.

## What a sensor must check (sdk-go `pkg/jobsig`)

Before it parses anything else of the command:

1. the envelope's `payloadType` is `application/vnd.openctem.job.v1+json`;
2. a signature whose `keyid` is a pinned key, or a key of the current
   verified key set when the sensor pins a root, verifies over the PAE of
   the payload bytes;
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

- **Root pin in the sensor's local policy** (RFC-040 §5.7): local policy
  v1 is frozen, so today the root is pinned by `SENSOR_JOB_SIGNING_ROOT`
  or at pairing; a later policy version can carry it.
- **`keyset_version` in the statement** (`signer.keyset_version`, RFC-040
  §5.6 point 3), once sensors that reject unknown statement fields are
  gone.
- **The signer's ledger and the scope document**: targets checked against
  the organization's approved scope and the zone's ranges, tiers, time
  windows, per-hour distinct-target ceilings; the signed scope document the
  sensor checks next to the job (RFC-040 §5.6 points 4 and 5).
- **Two-person rule for widening** the ledger (RFC-040 P2, then WebAuthn).
- **Template manifests, tool settings and egress policy** signed by the
  signer instead of the API's derived keys (decision Q11).
- **K2** (KMS, Vault Transit, HSM) and a Helm chart for the signer.
- Exporting the signing log to the SIEM and keyed audit checkpoints.
