# Sensors: vocabulary, code layout and protocols v1 and v2

> RFC: [RFC-023](../rfcs/RFC-023-scan-zones-and-scanners.md) §4 (D18) and §9.5.
> Contract of the rename: [RFC-023-sensor-rename-contract.md](../rfcs/RFC-023-sensor-rename-contract.md).
> Protocol v2: [RFC-026](../rfcs/RFC-026-sensor-results-ingest.md) (results) and
> [RFC-029](../rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md) (everything else; v1 deprecated).
> Routing of scanners by network: [scan-zones.md](scan-zones.md).

## Glossary

| Term | Meaning |
|---|---|
| **Sensor** | Software on the customer side that authenticates *to* the platform with its own key and heartbeat. The umbrella term; every row of the `sensors` table. |
| **Scanner** (role) | A sensor that assesses other hosts; routed by scan zone. What every existing sensor is today. |
| **Agent** (role) | A sensor installed on an endpoint that reports only about its own host. Since RFC-023 the word *agent* means this role only. |
| **Collector** (role) | A sensor that pushes data from systems inside the customer network. |
| **Integration** | An external system the *platform* calls (Jira, Slack, Splunk out, …); no software of ours runs for it. |
| `type` | The legacy v1 classification (`worker`, `scanner`, `sensor`, `collector`, `runner`). Kept as input and storage until role + deployment replace it (RFC-023 §9.1). |
| AI agent | The AI-triage "agent" mode (`AIModeAgent`, module `ai_triage.agent`): an LLM agent, unrelated to sensors. |

Until 2026-10 the code, database and API called sensors "agents". The rename
is complete in the API: packages, types, tables, columns, permissions
(`sensors:*`), management routes (`/api/v1/sensors`), audit ids (`sensor.*`),
log fields (`sensor_id`), metrics and API environment variables (`SENSOR_*`).

## Code layout

| Layer | Package |
|---|---|
| Domain | `pkg/domain/sensor` (entity, API keys, errors, repository interfaces) |
| Application | `internal/app/sensor` (service, selector, config templates); compat shim `internal/app/sensor_service.go` |
| Persistence | `internal/infra/postgres/sensor_repository.go`, `sensor_apikey_repository.go` |
| HTTP | `internal/infra/http/handler/sensor_handler.go` (management), `ingest_handler.go` / `command_handler.go` / `scansession_handler.go` (protocol v1) |
| Health | `internal/infra/controller/sensor_health.go`, `internal/infra/jobs/sensor_health_checker.go`, `internal/infra/redis/sensor_state.go` |
| Legacy vocabulary | `pkg/sensorproto/legacyv1` |
| Protocol v2 control plane | `pkg/sensorproto/v2/control.go` (wire), `internal/infra/http/handler/sensor_control_v2_handler.go`, `internal/app/command/transition.go` (idempotent transitions), mounted by `routes/sensor_v2.go` |
| Protocol v2 results | `pkg/sensorproto/v2` (wire), `internal/infra/http/middleware/ingest_v2.go` (edge), `internal/infra/http/handler/sensor_results_v2_handler.go`, `internal/infra/http/routes/sensor_v2.go`, `internal/app/ingest/v2*.go`, `strictjson.go`, `pkg/domain/ingestreport` |

## Protocol v1 and the legacy package

**Deprecated** (RFC-029 §5): served unchanged, but every v1 route with a v2
successor answers with `Deprecation: @1790812800`, `Sunset: Thu, 01 Apr 2027
00:00:00 GMT` and `Link: <successor>; rel="successor-version"` (see
[Protocol v2 control plane](#protocol-v2-control-plane) for the mapping).

Sensors and SDKs already deployed speak protocol v1: `/api/v1/agent/*`,
`agent_id` in responses, `agent_preference` in job payloads. That vocabulary
is frozen (RFC-023 §9.2 C1) and lives in exactly one package,
`pkg/sensorproto/legacyv1`, which also owns the deprecated management path
(`/api/v1/agents` → 308 to `/api/v1/sensors` until 2027-04-01) and the table
of renamed API environment variables. Handlers build v1 responses with its
types (`legacyv1.Command`, `legacyv1.ScanSession`, `legacyv1.Heartbeat`);
route registration and the route tooling resolve its path constants.

Two tests hold the line:

- `internal/infra/http/handler/protocol_v1_golden_db_test.go` replays the v1
  flow (heartbeat, poll, acknowledge, start, complete, fail, scan session,
  ingest, renew) against real repositories and compares the responses and the
  v1 route table with golden files recorded before the rename. The doorbell's
  additive fields are pinned separately in `doorbell.golden`; `flow.golden`
  runs with the doorbell on and is unchanged.
- `tools/lint/sensorvocab` fails on any Go identifier, import path or file
  path that says *agent* outside `legacyv1`, the rename tooling and the
  AI-agent identifiers.

## Suppression rules for the sensor-side gate

`GET /api/v1/agent/suppressions` (RFC-023 §9.2b, additive v1 route) returns
the sensor's tenant's approved, unexpired suppression rules as
`{"count": n, "rules": [{rule_id, tool_name, path_pattern, asset_id, expires_at}]}`.
The sensor's security gate (`-fail-on`) uses them to stop failing a CI job on a
finding the platform has suppressed. Tenant from the sensor identity; platform
sensors get 403; an empty list when the suppressions module is disabled.
Ingest applies the same rules server-side whatever the sensor does. Before this
route the SDK called the user route `/api/v1/suppressions/active` with its
sensor key and always got 401.

## Heartbeat doorbell

`POST /api/v1/agent/heartbeat` is also a doorbell (RFC-023 §9.2a): it tells
the sensor *that* something is waiting for it and when to ring again. It never
carries a job, a command text or any other payload. Jobs are still fetched and
claimed with `GET /api/v1/agent/commands` and
`POST /api/v1/agent/commands/{id}/acknowledge`, so authorization, the zone
claim predicate and claim semantics stay in one place.

### Response fields (additive, all `omitempty`)

| Field | Type | Meaning |
|---|---|---|
| `pending_jobs` | int | Commands this sensor could claim right now, capped at 100. Exactly what the poll would offer: pinned to the sensor or unpinned, pending, not expired, not scheduled for later, zone claim predicate (`zoneClaimPredicate`, incl. the tool match), capability gate. `> 0` ⇒ poll now. Not computed for platform sensors (no tenant poll). |
| `next_heartbeat_seconds` | int | Advised interval. 5 s while work is waiting, 30 s idle, 120 s when the doorbell query itself took ≥ 250 ms (platform under load). Clamped to `[SENSOR_HEARTBEAT_MIN_INTERVAL, SENSOR_HEARTBEAT_MAX_INTERVAL]` and never more than half of `WORKER_HEARTBEAT_TIMEOUT` (default 5 m ⇒ 150 s), so a sensor that follows it is never marked offline. |
| `actions` | []string | Typed directives from a closed set: `pause`, `resume`, `drain`, `rotate_key`, `update`. Rung today: `pause` (sensor disabled by an admin), `rotate_key` (the presented key expires within `SENSOR_KEY_RENEW_BEFORE`, default half of `SENSOR_KEY_TTL`). `resume`, `drain`, `update` are reserved. There is no free-form or shell verb (RFC-023 §10.4 R-4); a sensor ignores a value it does not know. |
| `config_version` | string | 16 hex chars, opaque. A digest of what the platform governs about the sensor: capabilities, tools, max concurrent jobs, execution mode, operator config, the presented key's expiry and the assigned scan zones with each zone's last change. Heartbeat metrics and `last_seen_at` are not part of it (both rewrite `sensors.updated_at` on every heartbeat, which is why `updated_at` cannot be the source). |

### Who gets what

A sensor announces it acts on the doorbell with the request header
`X-OpenCTEM-Sensor-Features: doorbell` (comma-separated list,
case-insensitive).

| | v1 sensor (no header) | doorbell-aware sensor |
|---|---|---|
| idle | plain v1 bytes `{"agent_id","status","tenant_id"}` | + `config_version`, `next_heartbeat_seconds: 30` |
| work waiting | + `pending_jobs`, `next_heartbeat_seconds: 5` | + `config_version` |
| key in renewal window | + `actions: ["rotate_key"]` | same |
| disabled | 401 `Invalid API key`, unchanged | **200** `actions: ["pause"]`, no other hint, no DB write |
| revoked / expired key | 401 | 401 |

The header gates the two things that would otherwise change what a deployed
v1 sensor sees: `config_version` is present on every heartbeat, and our
agent's start-up `TestConnection` is a heartbeat that exits on a 401 — a
disabled sensor answered with 200 would start and then fail every poll. The
disabled exception is matched on the exact method and path in
`AuthenticateSource`; every other route still refuses a disabled key.

### Light

One extra statement per heartbeat (`CommandRepository.PendingWorkForSensor`),
bounded by `LIMIT 100` per branch and a 1 s timeout. If it fails or times out
the heartbeat still answers 200 with no query-derived hints (the failure is
logged); `actions` that need no query are still sent. The statement splits the
poll's `(sensor_id = $s OR sensor_id IS NULL)` into two counts so each is an
index range on the existing partial indexes `idx_commands_pending_poll`
(tenant, sensor, status, …) and `idx_commands_pending_unassigned`, and
pre-filters unpinned zone commands to the sensor's own zones once instead of
running the zone subquery per row. The full predicate is still applied.

Measured on 100k commands (20k pending; the target sensor idle with 3 pinned
jobs among 15k pending jobs for other sensors, zones and capabilities —
the doorbell's worst case), `EXPLAIN (ANALYZE, BUFFERS)`, warm cache:

| Query | Time | Buffers |
|---|---|---|
| poll predicate as-is, wrapped in a count | 5.9 ms | 4 542 |
| shipped doorbell query | 2.4 ms | 194 |
| the poll itself (`GetPendingForSensor`) for comparison | 4.6 ms | 4 190 |

No new index: the suggested `(tenant_id, status, sensor_id) WHERE
status='pending'` already exists as `idx_commands_pending_poll`, and a trial
`(tenant_id, scan_zone_id) WHERE status='pending' AND sensor_id IS NULL` index
did not change the plan or the timing. The scan cannot be index-only because
the capability gate and tool match read `payload` (JSONB); the remaining cost
is the heap filter over the tenant's unpinned pending backlog, the same rows
every poll reads.

### Configuration

`SENSOR_HEARTBEAT_INTERVAL` (30s), `SENSOR_HEARTBEAT_BUSY_INTERVAL` (5s),
`SENSOR_HEARTBEAT_LOADED_INTERVAL` (2m), `SENSOR_HEARTBEAT_MIN_INTERVAL` (5s),
`SENSOR_HEARTBEAT_MAX_INTERVAL` (5m, further capped at half of
`WORKER_HEARTBEAT_TIMEOUT`), `SENSOR_HEARTBEAT_SLOW_QUERY` (250ms),
`SENSOR_KEY_RENEW_BEFORE` (default half of `SENSOR_KEY_TTL`, or 24h).

### What a sensor does with it

1. `pending_jobs > 0` ⇒ poll `GET /api/v1/agent/commands` immediately, then
   claim as today. No hint ⇒ keep the fixed poll interval (older servers).
2. Use `next_heartbeat_seconds` as the next heartbeat delay when present;
   fall back to the configured interval when absent.
3. With hints present, drop the separate fixed 30 s poll: poll on the doorbell
   only (plus once at start-up).
4. `pause` ⇒ stop polling and starting jobs, keep heartbeating; resume on the
   first heartbeat without `pause`. `rotate_key` ⇒ `POST /api/v1/agent/renew`.
   Ignore unknown actions.
5. A changed `config_version` means the platform changed something about this
   sensor; today the sensor can only log it (there is no v1 config endpoint),
   the v2 follow-up adds the fetch.

Code: `internal/app/sensor/doorbell.go` (hints, intervals, config version),
`internal/infra/postgres/command_repository.go` (`PendingWorkForSensor`),
`internal/infra/http/handler/ingest_handler.go` (`AuthenticateSource`,
`Heartbeat`), `pkg/domain/sensor/doorbell.go` (the `Action` enum). The wire is
pinned by `testdata/protocol_v1/doorbell.golden`.

## Outbox state on the heartbeat

A sensor built on an SDK with a durable outbox (results written to disk first,
delivered when the platform accepts them) reports the state of that queue on
the v1 heartbeat request, as an optional `outbox` object:

```json
"outbox": {
  "pending_count": 3,
  "pending_bytes": 123456,
  "oldest_age_seconds": 600,
  "dead_letter_count": 1,
  "evicted_count": 0
}
```

| Field | Meaning |
|---|---|
| `pending_count` | Items waiting to be delivered. |
| `pending_bytes` | Bytes on disk of those items. |
| `oldest_age_seconds` | Age of the oldest pending item, 0 when the outbox is empty. |
| `dead_letter_count` | Items the platform refused for good, kept in the sensor's dead-letter folder. |
| `evicted_count` | Items dropped by the outbox size/age cap since the sensor process started. |

The heartbeat request is decoded leniently, so older servers ignore the field
and older sensors simply do not send it. The heartbeat **response** does not
change: it stays the frozen v1 bytes.

**Stored.** The latest snapshot per sensor is kept in `sensors.outbox_stats`
(JSONB) with `sensors.outbox_reported_at` (server time, migration 000240).
Values are clamped on ingest (negative ⇒ 0; counts ≤ 10,000,000, bytes ≤ 2^50,
age ≤ 10 years). It is display data from an untrusted process: nothing
schedules, authorizes or bills on it. A disabled sensor's heartbeat writes
nothing, outbox included.

**A heartbeat without `outbox` leaves the stored snapshot untouched.** An SDK
without an outbox never sends the field, so its sensors show `outbox: null`. A
sensor downgraded to such an SDK keeps its last snapshot; `reported_at` shows
how old it is. An empty object (`"outbox": {}`) is a real report of an empty
outbox and replaces the snapshot.

**Shown.** `GET /api/v1/sensors` and `GET /api/v1/sensors/{id}` return

```json
"outbox": {"pending_count": 3, "pending_bytes": 123456, "oldest_age_seconds": 600,
           "dead_letter_count": 1, "evicted_count": 0, "reported_at": "2026-10-01T16:09:10Z"},
"outbox_warning": true
```

`outbox` is `null` when the sensor never reported one. `outbox_warning` is
true when results were lost or refused (`dead_letter_count > 0` or
`evicted_count > 0`) or delivery is stuck (`oldest_age_seconds > 3600`); false
when there is no snapshot. A sensor that is `online` with `outbox_warning` is
heartbeating but not getting its results through: check its log, the
dead-letter folder and the ingest errors for its tenant.

Code: `pkg/domain/sensor/outbox.go` (`OutboxStats`, `Clamp`, `Warning`),
`internal/infra/http/handler/ingest_handler.go` (`HeartbeatOutbox`),
`internal/infra/postgres/sensor_repository.go` (`UpdateHeartbeat`),
`internal/infra/http/handler/sensor_handler.go` (`SensorOutboxResponse`).

## Protocol v2 results ingest

[RFC-026](../rfcs/RFC-026-sensor-results-ingest.md) (decisions in its §10.1).
Sensors push results as CTIS only, declared by
`Content-Type: application/vnd.openctem.ctis.v1+json`, to a resource they
name. v1 ingest above is unchanged and still served. The wire vocabulary
lives in `pkg/sensorproto/v2` (golden files pin it); the contract is
`api/openapi/sensor-protocol-v2.yaml`.

### Routes

Mounted under `/api/v2/sensor` when `SENSOR_PROTOCOL_V2_RESULTS` is on (the
default). The group has its own authenticator: a sensor key in
`Authorization: Bearer` or `X-API-Key`. User JWTs, the session cookie and
`oct_` keys get `401`, sensor keys get `401` on every user route, and a
disabled sensor is refused on every v2 route.

| Method and path | Purpose |
|---|---|
| `GET /hello` | Protocol, features, media types, encodings, digests and the limits the SDK sizes segments from. |
| `PUT /results/{report_id}` | A whole report: segment 0 plus an implicit commit. |
| `PUT /results/{report_id}/segments/{seq}` | One segment, `seq` 0–255, any order. |
| `POST /results/{report_id}/commit` | `{"segment_count":n,"segment_digests":["sha-256=:…:",…]}`. |
| `GET /results/{report_id}` | The status resource. |
| `DELETE /results/{report_id}` | Abandon an uncommitted report (it becomes `expired`). |
| `PUT/POST /commands/{command_id}/results/…` | The same, bound to a command this sensor claimed (open, or finished under 15 minutes ago). Its tool is the only tool the report may name. |

`report_id` is a lower-case UUID the sensor chooses, unique per sensor. The
URL is the idempotency key and the content digest its fingerprint: the same
bytes again answer `200`, different bytes `409 report-conflict`.

### Edge chain (before any handler)

`middleware/ingest_v2.go`, in this order: per-tenant rate (the ingest
budget shared with v1), per-sensor rate and per-tenant in-flight cap (`429`);
`Content-Type` (`415` + `Accept`); `Content-Encoding` gzip/zstd, one coding
(`415` + `Accept-Encoding`); `Content-Length` required and at most 16 MiB
(`411`/`413`, before any byte is read); `Content-Digest` (RFC 9530, sha-256 or
sha-512, over the bytes **as sent**) present (`400 digest-required`) and
equal (`400 digest-mismatch`); then decoding with an output cap of
min(64 MiB, 100 × encoded size), an 8 MiB zstd window and decoder
concurrency 1 (`413 decompressed-too-large`). The handler reads only the
verified, bounded body. Then the strict decoder
(`internal/app/ingest/strictjson.go`): I-JSON (no duplicate member names,
valid UTF-8, no lone surrogates, depth ≤ 64, nothing after the value) and no
unknown fields (`422`), and the v2 report rules: body major version equals
the media type's, `tool.name` present, `metadata.id` empty or the report id,
≤ 10,000 findings and assets per segment.

The digest without a signature detects corruption and buggy proxies; it is
not authentication (anyone holding the key can compute it). RFC 9421
signing is iteration 2.

### Accept decisions

`internal/app/ingest/v2_receiver.go`: command binding, replay versus
conflict, every segment carries the same tool and metadata
(`409 segment-header-mismatch`), the same binding (`409 binding-mismatch`),
the report's tool is one the sensor declared (`422 tool-not-permitted`; a
sensor with no declared tools may report none, reserved names such as
`pentest` never), at most 8 open reports per sensor
(`429 too-many-open-reports`), the tenant's queue depth
(`INGEST_MAX_PENDING_PER_TENANT`, `429 queue-full`), and at most 100,000
assets and findings per report, reserved in one conditional `UPDATE` so
parallel segments cannot overshoot (`413 report-too-large`). The commit
must list exactly the received segments with their digests
(`409 segment-set-mismatch`). Stored: one `ingest_reports` row per report
with the server-stamped provenance (tenant from the key, sensor, command,
zone from the command, protocol, media type, user agent, receive time), and
one RFC-005 `ingest_jobs` row per segment plus one for the commit.

### Processing

The ingest worker runs v2 jobs whatever `INGEST_MODE` is
(`internal/app/ingest/v2_jobs.go`, `v2.go`). Each segment runs through the
v1 pipeline with the v2 options:

- **No fallback asset.** A finding binds to the asset its `asset_ref` names
  in its own segment, or to the segment's only asset when it names none.
  Anything else is rejected as an item (`asset_unresolved`, with a JSON
  pointer); no asset is made up from metadata.
- **No global catalog writes.** Findings link to CVE catalog rows that
  exist; the sensor's CVE text stays on the tenant's finding. The catalog is
  written by trusted feeds only.
- **Auto-resolve only on commit.** Once every segment of a committed report
  has an outcome, exactly one job claims the finalization: auto-resolve over
  the union of assets the report touched (full coverage, default branch, a
  tool the sensor declares), the branch-occurrence sweep and the finding
  counts. The **blinding guard** holds an auto-resolve that would close more
  than `SENSOR_V2_BLINDING_MIN_FINDINGS` (100) and more than
  `SENSOR_V2_BLINDING_RATIO` (50 %) of the open findings of that tool on
  those assets; the status then says `auto_resolve: held`.
- An uncommitted report expires 60 minutes after its last segment; its
  upserts stay and it never resolves anything. A segment's outcome is stored
  under its number, so a retried segment is never counted twice. Payloads
  are dropped once the report completes.

The status resource (`GET /results/{id}`) reports `receiving`, `queued`,
`processing`, `completed`, `failed` or `expired`, accepted/rejected counts,
up to 100 item errors (fixed details, never sensor bytes) and the
auto-resolve outcome. A partially accepted report is `completed`; the sensor
must not resend it. A `failed` report may be sent again under the same id.

### Discovery from v1

A v1 sensor that sends `X-OpenCTEM-Sensor-Features: results-v2` on its
heartbeat gets `X-OpenCTEM-Protocol: 2` back while v2 is on. Nobody else
sees the header and the body is unchanged (`flow.golden` runs with it on).
v2 responses carry `OpenCTEM-Protocol: 2`.

### Configuration and metrics

| Setting | Default | Meaning |
|---|---|---|
| `SENSOR_PROTOCOL_V2_RESULTS` | `true` | Mount `/api/v2/sensor`, process v2 jobs, advertise on the heartbeat. `false` unmounts it; v2 jobs already queued wait until it is on again. |
| `SENSOR_V2_BLINDING_RATIO` | `0.5` | Blinding guard ratio. |
| `SENSOR_V2_BLINDING_MIN_FINDINGS` | `100` | Blinding guard floor. |
| `INGEST_MAX_PENDING_PER_TENANT` | `100` | Shared with v1: queue depth per tenant. |

Migrations 000237 (`ingest_reports`, v2 columns on `ingest_jobs`) and 000239
(per-report item totals). Metrics: `ingest_v2_requests_total{route,method,outcome,problem}`,
`ingest_v2_bytes{stage=encoded|decoded}`, `ingest_v2_items_total{kind,result}`,
`ingest_v2_reports_total{state,auto_resolve}` and
`ingest_v1_requests_total{route}` (who still uses which v1 ingest route,
RFC-026 §8.3). Every label comes from a closed set.

## Protocol v2 control plane

[RFC-029](../rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md). Every
other sensor resource under `/api/v2/sensor`, in the same route group and
behind the same sensor-key authenticator as the results. Identity is the key
only: no `X-Agent-ID` (the API never read it). A tenant-less (platform)
sensor gets `403 scope-denied`. Each handler calls the service its v1 route
calls; only the wire differs. Bodies are JSON, decoded leniently (unknown
members ignored; at most 1 MiB, 4 MiB for `complete`, 8 MiB for the
fingerprint queries); errors are RFC 9457 problems; every response carries
`OpenCTEM-Protocol: 2`.

| v1 (deprecated) | v2 | Notes |
|---|---|---|
| `POST /api/v1/agent/heartbeat` | `POST /api/v2/sensor/heartbeat` | Same body. The doorbell is always on: `sensor_id`, `tenant_id`, `status` (`ok`/`paused`), `pending_jobs`, `next_heartbeat_seconds`, `actions`, `config_version` are always present. A disabled sensor gets `200` `paused` + `["pause"]` here, can still read `GET /hello`, and gets `401` everywhere else. |
| `GET /api/v1/agent/commands?limit=n` | `GET /api/v2/sensor/commands?limit=n` | `{"commands": [...]}`; a command carries `sensor_id` (null while unassigned). |
| `POST …/commands/{id}/acknowledge` | `POST /api/v2/sensor/commands/{id}/claim` | |
| `POST …/commands/{id}/start` | `POST /api/v2/sensor/commands/{id}/start` | |
| `POST …/commands/{id}/complete` | `POST /api/v2/sensor/commands/{id}/complete` | `{"result": …}` |
| `POST …/commands/{id}/fail` | `POST /api/v2/sensor/commands/{id}/fail` | `{"error_message": "…"}` |
| `GET /api/v1/agent/suppressions` | `GET /api/v2/sensor/suppressions` | Strong `ETag`; `If-None-Match` → `304`. |
| `POST /api/v1/agent/ingest/check` | `POST /api/v2/sensor/fingerprints/check` | ≤ 50,000 fingerprints (`422 too-many-items`). |
| `POST /api/v1/agent/ingest/baseline-diff` | `POST /api/v2/sensor/fingerprints/baseline-diff` | ≤ 50,000 fingerprints. |
| `POST /api/v1/agent/renew` | `POST /api/v2/sensor/keys` | `201`, `Cache-Control: no-store`; v1's per-sensor renewal budget. |
| `POST /api/v1/agent/ingest`, `/ingest/ctis`, `/ingest/chunk`, `GET /ingest/jobs/{id}` | `/api/v2/sensor/results/…` | RFC-026. |

Not deprecated (no successor yet): `/ingest/sarif`, `/ingest/recon`,
`/ingest/scan`, `/ingest/scanners`, `/scans`, `/telemetry-events`,
`/credentials/ingest`, `/api/v1/validation/evidence`.

**Transitions are idempotent** (`command.Service.Transition`). Repeating the
transition that produced the command's current state, by the same sensor
with the same body (a semantically equal `result`, the same stored
`error_message`), answers `200` with the command and runs no side effect
(pipeline progression, validation evidence, simulation finalisation run on
the real transition only). A different body is `409 transition-conflict`.
Any other state is `409 invalid-transition` with `"state"` (a pending
command past its expiry reads `expired`); a lost claim race is `409
command-claimed`; another sensor's or tenant's command is `404
command-not-found`. The state rules and the atomic claim are the v1 service's.

**Hello** lists `results` plus the control features (`heartbeat`,
`commands`, `suppressions`, `fingerprints`, `keys`) and
`deprecations.protocol_v1` (`deprecated_at`, `sunset_at`). An SDK uses v2
for a listed feature and v1 for the rest.

### Protocol telemetry

Every heartbeat records the protocol it arrived on and the client's
`User-Agent` (printable ASCII, ≤ 256 bytes) in `sensors.protocol_version`,
`protocol_client` and `protocol_seen_at` (migration 000247), in the
heartbeat update that already runs. `GET /api/v1/sensors` and
`GET /api/v1/sensors/{id}` return

```json
"protocol": {"version": 1, "user_agent": "openctem-sdk-go/0.8.1", "seen_at": "2026-10-02T09:00:00Z", "deprecated": true}
```

or `null` before the first heartbeat that recorded it. A sensor on sdk-go
0.8.x (v2 results, v1 heartbeat) reads `1`: it still needs the upgrade.
`sensor_protocol_requests_total{protocol, route}` counts every sensor request
by protocol and route name (closed sets).

## History written in the old vocabulary

Hash-chained audit rows (`agent.*`, resource type `agent`) and append-only
asset state history (`source = 'agent'`) are never rewritten. Reads treat
both spellings as one family: `audit.Action.Canonical`,
`audit.WithHistoricalActions`, `asset.ChangeSource.Canonical`,
`asset.WithHistoricalSources`.

## Upgrading an installation

Migration 000230 converts the schema and every stored value (see the contract,
§8). `server -sensor-upgrade-check` confirms nothing is left; the API also
logs a warning at startup when it finds leftovers. Branches written before
the rename catch up with `scripts/rename/sensor-rename.sh` (type-aware rename
of identifiers, packages, comments and files).
