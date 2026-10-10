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
envelope format, claim-time signing in the API, the key set signed by
an offline root through which sensors accept signer keys, and the signer's
scope ledger (RFC-040 P2): the signer signs a job only when its targets lie
inside the scope people approved, as the signer itself recorded it. Sensors verify
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
| `SIGNER_LEDGER` | scope ledger mode: `enforce`, `audit` or `off` ([Scope ledger](#scope-ledger)) | the recorded default: `enforce` on a signer that had never signed, `audit` on one upgraded to the ledger |
| `SIGNER_LEDGER_MIN_APPROVALS` | the operator's floor under every widening's approval count (0, 1 or 2) | 0 |

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
| 400 | `malformed` (not JSON, unknown or mistyped field, trailing data), `bad_kind`, `invalid_id`, `missing_command_type`, `missing_tool`, `bad_payload_digest`, `bad_targets`, `bad_templates`, `bad_limits`, `bad_lease_epoch`, `clock_skew`, `bad_expiry`, `server_field_set` |
| 403 | `out_of_ledger`, `tier_exceeds_ledger`, `target_excluded`, `template_not_in_ledger` (the [scope ledger](#scope-ledger) does not authorize the job) |
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
- the organization's and the sensor's signing ceilings;
- every target against the organization's [scope ledger](#scope-ledger), at
  the tool's tier (in `enforce` mode; `audit` signs and records the miss).

It does not yet check zone ranges, time windows or per-hour distinct-target
ceilings (see "Not yet").

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
| `templates` | string[] | only when the payload carries custom templates: `sha256:` + hex SHA-256 of each `custom_templates[].content`, base64-decoded after trimming, in payload order, duplicates kept ([Custom templates](#custom-templates)) |
| `limits` | object[] | only for a sensor that enforces scope limits, when a target is covered only by port- or path-limited entries: `{host, ports, protocol, path_prefix}` per covering entry ([Scope limits](#scope-limits)) |
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
10. it runs `tool` against `targets`, and its local policy agrees;
11. `templates` lists exactly the digests of the payload's custom
    templates; it then trusts those template bytes through the job
    ([Custom templates](#custom-templates));
12. every `limits` entry names the host of one of `targets` and is well
    formed; the sensor then enforces them ([Scope limits](#scope-limits)).
    A sensor that predates the field refuses the statement (unknown field).

Any failure: refuse the command (fail it with a refusal), never run it.

## Scope limits

A target that only port- or path-limited scope entries cover
(`api.x.com:8443/tcp`, `https://x.com/api/`) may be scanned only within the
limit (RFC-065 §16.8). Tools that stay on their target (`naabu` with a port
list inside the limit, `httpx`) run there on any sensor. A crawler, a
template scanner or a top-ports scan runs there only on a sensor that
enforces the limits:

- the sensor reports `scope.limits@1` in its manifest (sdk-go
  `scopelimit.Capability`). It does so only when its tools run out of
  process in a sandbox that confines their network to the task's egress
  forwarder;
- jobs are signed (the claim re-check treats the capability as absent
  without a job signer);
- at claim the command service computes the limits of the job's targets
  from the tenant's scope (`ActiveGate.StatementLimits`: one limit per
  covering entry, on the target's host; a host an unlimited entry covers has
  none) and puts them in the statement. The signer checks each against its
  ledger (point 5 above).

On the sensor, the limits come from the verified statement only, never from
the payload. The task's forwarder refuses a connection to a limited host on
any other port. On a port whose limits name a path prefix it reads every HTTP
request, terminating TLS with a per-task authority, and refuses with `403`
(recorded in the task's egress records) a request whose Host is not the
destination or whose decoded, dot-segment-free path is not under a prefix.
Tool flags (naabu's port list, katana's crawl scope) are set as well, but
nothing relies on them.

A sensor that does not report the capability never gets such a job: the
claim re-check withholds it (it stays pending for an enforcing sensor)
rather than narrowing or failing it.

## Failure behaviour

- `SIGNER_SOCKET` unset: claims are exactly as before; no envelope, no
  `signed_jobs` feature.
- Signer refusing for its ledger (403: `out_of_ledger`,
  `tier_exceeds_ledger`, `target_excluded`): the claim is taken back and the
  command **fails** with `SIGNER_REFUSED: the job signer refused to sign this
  job (<reason>): <detail>`, so it is not offered again; its run step,
  validation or retest fails with the same code (failure class `scope`).
- Signer down, slow (over `SIGNER_TIMEOUT`) or refusing for another reason:
  the command is not handed out. A claim-N answer leaves it out; a claim by id answers `503`
  `unavailable` with `Retry-After`. The claim is taken back: the command is
  pending again, still addressed to the sensor only if it was before the
  claim. A claim replay (the sensor already holds the command) is answered
  `503` and the command is left as it is. Claims wait; nothing leaves
  unsigned.
- Each signing is counted in `sensor_job_signing_total{outcome}` with
  `outcome` one of `signed`, `refused`, `unavailable`; each refusal in
  `openctem_signer_refusals_total{reason}` (alerts `SignerOutOfLedger`,
  RFC-040 §5.11 A10, and `SignerRefusals`), and refusals are logged with the
  command and sensor ids. The signing log is the record a compromised API
  cannot rewrite; the metric is the alerting signal the API reports.

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
  `openctem-signer verify-log` checks it. A job signed in `audit` mode that
  `enforce` would have refused carries `ledger_audit` (the reason).
- `ledger.log`: the scope ledger, in the same chained JSONL format (lines up
  to 32 MiB); the ledger is the replay of it. `ledger.lock` is held while the
  signer runs, so an import cannot write beside it. See
  [Scope ledger](#scope-ledger).

## Scope ledger

RFC-040 §5.6 points 4 and 5, phase P2. The signer keeps, per organization,
the scope entries in effect and the target exclusions, in its own state
directory, and signs a job only inside them. The API's database is not
consulted: a `scope_targets` row written straight into the database, or an
API process that asks for anything, gets a refusal.

### What it holds and checks

| Item | Fields | From |
|---|---|---|
| entry | `id`, `type` (scope target type), `pattern`, `max_tier` (0, 1, 2), `expires_at`, `ports` and `protocol` (the port limit, canonical form; absent: none) | a scope entry in effect (active, unexpired) |
| exclusion | `id`, `type` (domain, subdomain, ip_address, ip_range, cidr, url, repository), `pattern`, `expires_at` | a target exclusion in effect (approved, active) |

At sign time, for every target of the statement, with the API's matching
(`pkg/domain/scope`: `*.x` covers `x` and every name below it, CIDR and
range containment, IDNA forms; the same `AuthorityForms`, `ExclusionForms`
and `NeedsAuthority` the API's authority check uses):

1. an exclusion in effect that matches the target, its URL host or
   host:port host: `target_excluded` (whatever the tool's tier);
2. the tool's tier is `stage.ProbeTier(tool)` from the catalog compiled into
   the signer (an unknown tool or none is t1). A passive (t0) tool needs no
   entry, and neither do internal names and private, loopback, link-local or
   CGNAT addresses (zones gate them), as in RFC-054 §4.2;
3. otherwise an unexpired entry covering the target with `max_tier` at or
   above the tier: covered only below it is `tier_exceeds_ledger`, not at all
   `out_of_ledger`. Matching is `scope.EntryMatches`: a port-limited entry
   covers only a target that names an allowed port (`host:port`, or a URL
   whose port is allowed), a URL entry with a path only URLs under it;
4. a target covered only by port- or path-limited entries is signed only for
   a tool that stays on the target it is given
   (`scope.ConstrainedToolAllowed`), or for any tool when the statement
   carries `limits` for the target's host; otherwise `out_of_ledger`. The
   job's port list is checked by the API at claim (the signer does not see
   the payload);
5. each statement limit must lie within an entry in effect at the tool's
   tier that covers one of the statement's targets on that host
   (`scope.LimitWithin`: ports a subset, the same protocol, a path prefix at
   or under the entry's path, segment by segment): `out_of_ledger`
   otherwise. A malformed limit, or one for a host the statement does not
   target, is `bad_limits` (400).

The port limit is part of an entry like its pattern: dropping or relaxing
it is a widening (approvals as for a new entry), and a sync from the
database removes an entry whose limit differs instead of taking the new
one. A limit that is not in canonical form is malformed.

Expiry is applied with the signer's clock: an expired entry stops
authorizing without any message from the API.

### How it changes

Three paths, nothing else:

| Path | Who | What the signer allows |
|---|---|---|
| `POST /v1/ledger/apply` | the API's scope service, on every committed change to what authorizes probes | narrowing always; widening only with the approvals below |
| `POST /v1/ledger/sync` | the API, every 10 minutes (`signer-ledger-sync` controller) for every organization the ledger holds | narrowing only |
| `openctem-signer ledger import` | the operator, signer stopped | the bootstrap, or a restore with `-replace` |

`apply` body (`jobsign.LedgerChange`, unknown fields refused, at most 16 MiB
and 1,000 operations; an organization holds at most 10,000 entries and
10,000 exclusions):

```json
{"tenant_id": "…", "change_id": "<uuid>",
 "requester": "<user uuid, or empty for a system path>",
 "approvals": [{"user_id": "<uuid>", "approved_at": "…", "self_approved": false}],
 "policy_required_approvals": 1,
 "platform_policy": "",
 "ops": [{"op": "put_entry", "entry": {"id": "…", "type": "domain", "pattern": "*.example.com", "max_tier": 1}},
         {"op": "remove_exclusion", "id": "…"}]}
```

Operations: `put_entry`, `remove_entry`, `put_exclusion`,
`remove_exclusion`. The **signer** classifies the change; the caller does
not say which it is. A change widens when any operation widens
(`jobsign.EntryWidens`, `ExclusionPutWidens`, `ExclusionRemoveWidens`): a
new entry, a different type or pattern, a higher tier, a later or removed
expiry; an exclusion removed or shortened while in effect. Everything else
narrows, and identical puts are a no-op.

A widening needs, counted by the signer: distinct approvers (lower-case
UUIDs, `approved_at` not in the future), **not the requester**, at least
`max(policy_required_approvals, SIGNER_LEDGER_MIN_APPROVALS)`, and at least
one when an entry is t2 (RFC-054 S3: never zero for intrusive). A
requester's plain approval never counts; a `self_approved` approval (RFC-054
§12 A2, a sole owner with a fresh second factor) counts once and only for
the requester. A t2 entry without an expiry is malformed. The approval count
is the API's scope policy (`scope.Service.loadPolicy`): there is no second
approver model here.

Refusals: 400 `ledger_malformed`, 413 `ledger_too_large`, 403
`ledger_not_approved`. The answer is `{"kind": "widen|narrow|noop", "mode": "…"}`.

`sync` body (`jobsign.LedgerSnapshot`): the organization's entries and
exclusions in effect in the database. Entries the snapshot lacks are
removed; entries it holds narrower are narrowed (lower tier, earlier
expiry); exclusions it holds that the ledger lacks are added, and the
later of two exclusion expiries is kept. Anything the snapshot holds wider
is left out and counted as `diverged` (the API logs it). `GET /v1/ledger`
answers the mode and the organizations with anything in the ledger.

### The API side (the hook)

`scope.Service` sends every change through two functions,
`commitEntry` and `commitExclusion` (`internal/app/scope/ledger.go`): create,
update, approve, activate, deactivate and delete of entries; approve,
activate, update, deactivate and delete of exclusions. Writes made outside
it go through `scope.Service.CommitEntries`, the same rule in batch form:
bounty programs (RFC-065) send import, re-import and resume as widenings
(requester the importer, no approval, `platform_policy:
program_attestation`) and pause, end and dropped entries as narrowings.
Authorization-letter entries (RFC-065 §13) go through `commitEntry` like
any entry, and the ledger holds them with the letter's `valid_until` as
their latest expiry, so they leave it with the letter without a sync; a
revoked letter narrows the organization's ledger at once
(`Service.NarrowLetter`, a sync of that organization). Program exclusions
and the rule that program targets never go to platform sensors stay
API-side checks; the ledger does not hold them.

No other path may write scope: `internal/app/scope/ledger_guard_test.go`
fails the build when SQL writing `scope_targets` or `scope_exclusions`
appears outside the known repository methods, when the scope or programs
service calls a repository write outside the hook (unless allowlisted with
the reason it cannot change the ledger: declining a pending entry or
exclusion, creating a pending exclusion, the time-based expiry sweeps), or
when a scope repository is constructed or handed out at a new site.

- A **widening is sent before it is saved**. Refused, the request fails with
  `409 SCOPE_LEDGER_REFUSED`; signer down, `409 SCOPE_LEDGER_UNAVAILABLE`.
  The database never holds scope the signer did not accept.
- A **narrowing is saved first** and sent best effort; it is never blocked
  by the signer. One that did not arrive is applied by the next sync.
- The approvals sent are the entry's recorded approvals, its requester
  (`created_by`, or whoever last widened it) and its `approvals_required`;
  for an exclusion taken out of effect, the reviewer that
  `Exclusion.AuthorizeReduction` accepted, with one approval required.
- An exclusion whose window was extended back to review stays in the ledger
  as it was until it is approved again (the ledger keeps the stricter).

Path, finding-type and scanner exclusions are not target sets and stay out
of the ledger.

### Modes and defaults

| Mode | Sign time | Ledger changes |
|---|---|---|
| `enforce` | a target outside the ledger is refused (403) | validated and recorded |
| `audit` | signed anyway; the signing log line carries `ledger_audit` and the signer logs a warning | validated and recorded |
| `off` | not checked | answered `{"mode": "off"}`, not recorded |

`SIGNER_LEDGER` sets the mode. Unset, the default recorded in the ledger's
first line applies: **`enforce` for a new installation** (the signer had
never signed when the ledger was created) and **`audit` for an upgraded
one** (its signing log already had entries), as decided for the sensor-local
policy (RFC-040 Q3 revised: new installs fail closed). An import sets the
default to `enforce`.

### Bootstrap and restore (the ceremony)

An upgraded installation starts in `audit` with an empty ledger: every job
is still signed, and each one outside the ledger is recorded. To enforce:

1. Export the scope in effect from the database (a new file, 0600; never
   overwritten). Its SHA-256 is printed:

   ```bash
   docker compose exec api ./server -signer-ledger-export /tmp/ledger.json
   docker compose cp api:/tmp/ledger.json ./ledger.json
   ```

2. Review it (`jq` it; a second person compares the organizations and
   patterns with the Scoping pages).
3. Stop the signer and import from standard input; the digest printed must
   equal step 1's:

   ```bash
   docker compose stop signer
   docker compose run --rm -T signer ledger import -file /dev/stdin < ledger.json
   docker compose start signer
   ```

   The import refuses while the signer runs (it holds `ledger.lock`) and,
   into a ledger that already holds scope, unless `-replace` is given:
   `-replace` is for restoring after the signer's state was lost, and it can
   widen the ledger, so it belongs to the same two-person review.
4. The default mode is now `enforce` (unless `SIGNER_LEDGER` says
   otherwise). Watch `openctem_signer_refusals_total` and the
   `SignerOutOfLedger` alert.

`openctem-signer ledger verify` checks the chain of `ledger.log` and that
every record replays; `openctem-signer ledger show` prints the ledger as a
snapshot file (read only, also while the signer runs). A tampered,
reordered or truncated `ledger.log` stops the signer at start.

### Limits (P2)

- **Approvals are as the API recorded them.** The signer checks the
  approval rule (count, distinct people, not the requester, the operator
  floor, t2), but the user ids and the policy count come from the API. An
  attacker who controls the API process can claim approvals; the ledger
  then still stops a database writer, a path that bypasses the scope
  service, and every target outside approved scope, and the chained
  ledger log records each claimed approval. P3 makes each approval a
  WebAuthn assertion the signer verifies. `SIGNER_LEDGER_MIN_APPROVALS`
  raises the floor in the meantime.
- Internal names and private addresses are not checked against entries
  (zones gate them, as in the API); the sensor-local policy is their
  control until zone ranges join the ledger.
- Tenant approval settings (`widening_approvals`) are read by the API; a
  lowered setting lowers the count the API reports. The operator floor
  is the signer-side bound.

## Custom templates

RFC-040 §5.8 and §11.5. A custom template version reaches a sensor only
when people approved it and the signer recorded its digest in the ledger.

- **Approval.** A template version (its content) is approved for sensors
  like a scope widening: the organization's approval count from the scope
  policy (`scope.Service.EffectiveApprovals`), approvers holding
  `attack_surface:scope:approve`, with step-up, never the author of the
  version (`content_author_id`: the creator, or whoever changed the
  content). `POST /api/v1/scanner-templates/{id}/approve` records one
  approval; once the count is reached the API sends `put_template {id,
  sha256}` to the signer, a widening checked by the same rule as scope
  entries, before the version is saved as approved (`ledger_sha256`).
  With a count of 0 a new version is approved when it is saved. Approvals
  belong to one version (`sensor_approvals[].sha256`): new content needs
  new approvals, and the old version leaves the ledger
  (`remove_template`). Deprecating or deleting a template removes it.
  Templates synced from a source get no author and need an approval for
  each new version. Without a job signer nothing changes: no approval is
  asked.
- **At claim time** the API lists the digests in the statement
  (`templates`). The signer refuses a job with a digest no approved
  version has (`template_not_in_ledger`, 403): the command fails with
  `SIGNER_REFUSED`. A template whose content does not decode fails the
  command before the signer is asked.
- **On the sensor** (sdk-go): a verified statement whose `templates` equal
  the payload's digests makes the templates trusted without
  `SENSOR_TEMPLATE_SIGNING_KEYS`; the local `allow_custom_templates` gate
  and the template protocol checks still apply. A sensor without signed
  jobs keeps the per-tenant manifest (RFC-038 §6.12), signed with a key
  the API derives: that path is the fallback and is removed once signed
  jobs are required everywhere. Older sdk-go verifiers refuse statements
  carrying `templates` (unknown field): such jobs fail closed on them.
- **Upgrade.** Migration `001572` marks the current version of every
  active template as approved (they ran before); the ledger bootstrap
  exports them for review.

## Not yet (next steps)

- **Root pin in the sensor's local policy** (RFC-040 §5.7): local policy
  v1 is frozen, so today the root is pinned by `SENSOR_JOB_SIGNING_ROOT`
  or at pairing; a later policy version can carry it.
- **`keyset_version` in the statement** (`signer.keyset_version`, RFC-040
  §5.6 point 3), once sensors that reject unknown statement fields are
  gone.
- **The scope document** (P3): the approved part of the ledger signed by
  the offline root's delegated scope role and checked by the sensor next to
  the job (RFC-040 §5.6 point 4, two repositories); zone ranges, time
  windows and per-hour distinct-target ceilings in the ledger.
- **WebAuthn approvals** (P3): each approval an assertion over the change
  digest, verified by the signer against approver credentials enrolled
  through its own CLI, so a compromised API cannot invent approvals.
- **Tool settings and egress policy** signed by the signer instead of the
  API's derived keys (decision Q11); the per-tenant template manifest key
  removed once signed jobs are required everywhere
  ([Custom templates](#custom-templates)).
- **K2** (KMS, Vault Transit, HSM) and a Helm chart for the signer.
- Exporting the signing log to the SIEM and keyed audit checkpoints.
