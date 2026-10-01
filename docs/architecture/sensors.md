# Sensors: vocabulary, code layout and protocol v1

> RFC: [RFC-023](../rfcs/RFC-023-scan-zones-and-scanners.md) §4 (D18) and §9.5.
> Contract of the rename: [RFC-023-sensor-rename-contract.md](../rfcs/RFC-023-sensor-rename-contract.md).
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

## Protocol v1 and the legacy package

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

## Protocol v2 results ingest (proposed)

[RFC-026](../rfcs/RFC-026-sensor-results-ingest.md) defines how sensors push
results in protocol v2: CTIS only, declared by
`Content-Type: application/vnd.openctem.ctis.v1+json`, sent as
`PUT /api/v2/sensor/results/{report_id}` (self-describing segments plus a
commit for large reports), with a mandatory `Content-Digest`, `202` + a status
resource, and provenance stamped by the server. Raw SARIF and other files go
to a separate user-authenticated import API. v1 ingest above is unchanged.

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
