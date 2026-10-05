# Sensors: vocabulary, code layout and protocols v1 and v2

> RFC: [RFC-023](../rfcs/RFC-023-scan-zones-and-scanners.md) §4 (D18) and §9.5.
> Contract of the rename: [RFC-023-sensor-rename-contract.md](../rfcs/RFC-023-sensor-rename-contract.md).
> Protocol v2: [RFC-026](../rfcs/RFC-026-sensor-results-ingest.md) (results) and
> [RFC-029](../rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md) (everything else; v1 deprecated).
> Routing of scanners by network: [scan-zones.md](scan-zones.md).
> Proxies and network egress (proposed): [RFC-034](../rfcs/RFC-034-sensor-network-egress.md),
> section [Network egress and proxies](#network-egress-and-proxies-rfc-034-proposed).
> Trust between sensors and the platform (what each side verifies about the
> other, current gaps): [sensor-platform-trust.md](sensor-platform-trust.md),
> [RFC-040](../rfcs/RFC-040-platform-sensor-mutual-distrust.md) (proposed).

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
| `next_heartbeat_seconds` | int | Advised interval. 5 s while work is waiting or while a command the sensor claimed was canceled within the last lease period (so it hears `cancel_command_ids` within seconds), 30 s idle, 120 s when the doorbell query itself took ≥ 250 ms (platform under load). Clamped to `[SENSOR_HEARTBEAT_MIN_INTERVAL, SENSOR_HEARTBEAT_MAX_INTERVAL]` and never more than half of the offline distance (45 s: half the ladder's 90 s floor, or of `WORKER_HEARTBEAT_TIMEOUT` when shorter; RFC-035 D2). The heartbeat stores the advice as the sensor's deadline ("Fleet health"), so a sensor that follows it is never marked offline. |
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
`SENSOR_KEY_TTL` defaults to 90 days (RFC-032 Phase 0; `0` turns expiry
off): a renewed key expires after it, so `rotate_key` rings 45 days before.
Only renewal applies it. A key created or regenerated by an administrator
never expires; a sensor that renews (SDK v0.12+ on a persistent state
volume, or any sensor with `PLATFORM_KEY_AUTORENEW=true`) replaces it with an
expiring key on its first start, and one that does not keeps it. A sensor
that renewed while the TTL was off recorded its key as non-expiring and keeps
it until the key is regenerated (no `rotate_key` is rung for keys without an
expiry: sensors that cannot renew would log it on every heartbeat).
`SENSOR_KEY_RENEW_GRACE` (default 15m) is how long the key a sensor renewed
with keeps working after the renewal; every other key the sensor held stops
at the same moment, so a renewal leaves one long-lived key (see
[agent-identity.md](agent-identity.md#renewal-retires-the-presented-key)).

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

## Fleet health (Sensors page)

`GET /api/v1/sensors`, `GET /api/v1/sensors/{id}` and `GET /api/v1/sensors/stats`
carry a computed view of each sensor, so every client shows the same answer to
"can this sensor take work, and if not, why". Nothing here is stored; it is
computed on read (`pkg/domain/sensor/fleet_health.go`, `AssessHealth`).

**State ladder** (`state`), first match wins:

| State | When |
|---|---|
| `revoked`, `disabled` | admin status |
| `never_connected` | no heartbeat yet |
| `online` | its next heartbeat is not past due (deadline + grace, below) |
| `degraded` | online and at least one health reason |
| `idle` | a one-shot (CI, `standalone`/`runner`) sensor between runs: it connects only while it runs, so no heartbeat is normal |
| `offline` | convicted by the health controller (`health = 'offline'`), or past the offline step and silent longer than `WORKER_HEARTBEAT_TIMEOUT` |
| `late` | past its deadline + grace; still takes work |
| `stale` | well past its deadline; takes no new work. Also a sensor past the offline step that the controller has not convicted yet (it holds convictions while the platform is slow) |

**Heartbeat deadline** ([RFC-035](../rfcs/RFC-035-sensor-control-plane-under-load.md)
§5.6, migration 000261). Every heartbeat stores the interval the sensor
follows (`sensors.heartbeat_interval_seconds`) and the deadline of its next
heartbeat (`heartbeat_due_at` = now + interval). The interval is the longer
of the `control.interval_s` the sensor reports and, for a sensor that follows
the doorbell (protocol v2, or v1 with the `doorbell` feature), the
`next_heartbeat_seconds` just advised; 60 s (the SDK default) for a sensor
that does neither, and for rows that have not heartbeated since the
migration. It is clamped to 1–300 s. Any authenticated request also proves
the sensor alive, so the effective deadline is the later of `heartbeat_due_at`
and `last_seen_at` + interval.

With `grace = max(10 s, 0.2 × interval)` (`pkg/domain/sensor/liveness.go`,
`Ladder`, the one implementation the controller and the fleet view share):

| Step | Until | Stored `health` | Dispatch | Pinned pending work | Notified |
|---|---|---|---|---|---|
| online | due + grace | `online` | yes | kept | no |
| late | due + 2 × interval + grace | `late` | yes | kept | no |
| stale | due + max(3 × interval, 90 s) | `stale` | no | released to the zone | no |
| offline | beyond | `offline` | no | released | `sensor.offline`, audit `sensor.disconnected`, activity entry |

At the default 30 s idle interval a silent sensor is late 40 s after its last
heartbeat, stale at 100 s and offline at 120 s; a busy sensor (5 s) is stale
after 25 s and offline after 95 s; one told to back off (45 s) is offline
after 180 s. The health controller (`internal/infra/controller/sensor_health.go`,
every 30 s) writes the steps; only a request moves a sensor back to
`online`. Dispatch, zone routing and tool availability take `health IN
('online', 'late')`; `ReleasePendingFromUnavailableSensors` unpins work held
by `stale` and `offline` sensors. A heartbeat from a `late` or `stale` sensor
is not a reconnect (no `sensor.connected` audit row).

`GET /sensors/{id}` also returns `heartbeat_interval_seconds`,
`heartbeat_due_at`, `heartbeat_state` (the ladder step now) and `control`.
`GET /sensors/stats` returns `online_window_seconds` (how long a sensor on the
idle interval stays online: interval + grace) and `offline_after_seconds`
(`WORKER_HEARTBEAT_TIMEOUT`, the backstop above).

**Health reasons** (`health_reasons[]`: `code`, `severity`, `message`), listed
whatever the state: `outbox_backlog` (results waiting over an hour),
`outbox_dead_letters`, `outbox_evicted`, `key_expired`, `key_expiring` (within
7 days), `identity_cloned` (two live processes use the key; see "Key use and
cloned identities"), `version_unsupported`, `sdk_unsupported` (see "Build information"),
`no_tools` (a scanning daemon with no tools), `error_reported`,
`heartbeat_late` (the sensor is late or stale, or its last delivered heartbeat
came more than 1.5 intervals after the previous one, `control.gap_s`) and
`control_slow` (`control.lag_ms` or `build_ms` above 5 s). An online sensor
with any reason is `degraded`.

**Release channel**: `SENSOR_LATEST_VERSION` (default: the newest sensor release
when the API was built, `none` turns it off) and `SENSOR_MIN_VERSION` (default
none). `version` is normalized to one form (`0.4.2`, `v0.4.2` and `vv0.4.2` all
read `v0.4.2`); `version_status` is `latest`, `update_available`, `unsupported`
or `unknown` (no version, a dev build, or no channel). A git-describe build
(`v0.4.2-3-gabc1234`) counts as its tag. Both settings are in the stats
response (`latest_version`, `min_version`).

**Other fields**: `key_expires_at`, `last_offline_at`, `last_error_at`,
`started_at` and `uptime_seconds` (from the heartbeat's `uptime_seconds`, stored
as `sensors.process_started_at`, migration 000249), `is_platform_sensor`.
`ip_address` is the heartbeat's client address under the trusted-proxy rule
(`SERVER_TRUSTED_PROXIES`): behind the built-in gateway it is the address the
gateway saw (`X-Real-IP`), so a sensor running in a container on the platform
host shows the container network's gateway address, which is where it really
connects from.

**Stats** count the same rows the list returns: the tenant's own sensors.
Shared platform sensors (`is_platform_sensor`) are in neither; their capacity
is `GET /api/v1/platform/stats`, shown on its own page. Their queue
(`get_next_platform_job`) is shared fairly across tenants: within a priority
class, the tenant with the fewest platform jobs in flight goes first
(migration 000461, RFC-030 §5.7). The stats also add `by_state` (every state, zeros included), `by_version_status`,
`needs_attention`, `can_take_jobs`, `jobs_running` and `job_slots`.

## Build information

The platform knows which sensor product, version, commit and SDK each sensor
runs (`pkg/domain/sensor/build.go`, `ResolveBuild`). A heartbeat (v1 and v2,
additive and optional) may carry:

```json
{"sdk": {"name": "openctem-sdk-go", "version": "0.9.0"},
 "sensor": {"name": "openctemio-sensor", "version": "0.5.0", "commit": "abc1234", "build_time": "2026-10-01T12:00:00Z"}}
```

The members are read leniently: a member of another shape, or a field that is
not a string, is ignored, never a reason to refuse the heartbeat. Every part a
heartbeat leaves empty is taken from the User-Agent the SDK sends
(`<product>/<version> openctem-sdk-go/<sdk version>`), so sensors that predate
the members are populated too; the generic `sdk/1.0` of older SDKs carries
nothing. Values are untrusted and reduced to safe tokens: names
`[a-z0-9._-]` (64), versions must be release versions and are normalized
(`v0.9.0`), commits hex (7-40), build times RFC 3339 no later than a day ahead.
The top-level `version` member stays the sensor version (`sensors.version`);
`sensor.version` and then the User-Agent product version are used only when
it is empty. Stored in `sensors.sdk_name`, `sdk_version`, `sensor_product`,
`sensor_commit`, `sensor_build_time` (migration 000255); an empty part leaves
the stored value.

**SDK policy**: `SENSOR_SDK_MIN_VERSION` and `SENSOR_SDK_LATEST_VERSION`
(default none; `none` turns one off). `sdk_status` per sensor is `unsupported`
(below the minimum: health reason `sdk_unsupported`, so a heartbeating sensor
is `degraded`), `outdated` (below the latest), `current`, or `unknown` (no SDK
version known). The sensor responses carry `sdk_name`, `sdk_version`,
`sdk_status`, `sensor_product`, `sensor_commit`, `sensor_build_time`; the stats
add `sdk_min_version`, `sdk_latest_version`, `by_sdk_version` (`unknown` for
none) and `by_sdk_status`; `GET /sensors?sdk_version=v0.9.0` (or `unknown`)
filters on it.

## Activity

`GET /api/v1/sensors/{id}/activity?types=&cursor=&limit=` is the sensor's
timeline, newest first (`sensors:read`). It merges three sources, none copied
into another:

| Category | Types | Source |
|---|---|---|
| `status` | `online`, `offline`, `restarted`, `key_ip_changed`, `identity_cloned` | `sensor_events` |
| `updates` | `version_changed`, `sdk_version_changed`, `protocol_changed`, `tools_changed`, `capacity_changed`, `content_updated`, `content_refresh_failed` | `sensor_events` |
| `jobs` | `job_claimed`, `job_completed`, `job_failed`, `job_canceled`, `job_expired` | `commands` (`acknowledged_at`, `completed_at`) |
| `people` | `audit` | `audit_logs` |

The audit log keeps administrator actions; operational history lives in
`sensor_events` (migration 000255) so the tamper-evident chain stays lean.
The server writes events, never the sensor:

- **Heartbeat diff** (`sensor.DiffHeartbeat`, called from `UpdateHeartbeat`
  with the row it already reads): a restart (`process_started_at` moved more
  than 15s forward, with the downtime since the last heartbeat), a new sensor
  version (upgrade / downgrade), SDK version, protocol (`1 -> 2`), installed
  tools (added / removed / version bumps), effective job capacity, and scanner
  content versions or refresh errors. A part the heartbeat does not carry, or
  that was never reported before, is not a change.
- **Health transitions**: `online` when a heartbeat arrives for a sensor that
  was not online (with how long it was offline), `offline` when the health
  checker marks it offline. `stale` is computed on read and has no event.

**Limits**: identical consecutive events (the latest event of the same
category has the same type, and the same summary for updates) within 10
minutes fold into one row (`repeat_count`, `last_at`); at most 30 rows per
sensor per category per hour, the rest are dropped, so a flapping sensor
cannot crowd out its updates. `sensor-event-retention` deletes events after 90
days. Platform sensors (no tenant) record nothing. A failed event or audit
write is logged as a warning and never fails the heartbeat.

**Audit items** are returned only when the caller also holds `audit:read`
(owners and administrators); `audit_included` in the response says whether
they were. They include rows written before the rename (`agent.*`, resource
type `agent`), returned under their current names; a historical
`connected`/`disconnected` row is a `status` item (`online`/`offline`), and one
the server also wrote as an event appears once, as the event.

**Paging**: `next_cursor` is opaque (the last item's time and key); each
source is cut at the cursor and limited on its own, then merged, so pages
never skip or repeat an item. `limit` is 1-100 (default 30).

## Install snippets

`GET /api/v1/sensors/{id}/config-templates` renders the snippets the Sensors
page shows: `docker` (docker run), `compose` (compose.yaml), `kubernetes`
(Secret + PVC + Deployment; a Job for a one-shot sensor), `helm` (turns on the
sensor bundled with the openctem chart), `yaml` (sensor.yaml), `env`, `cli`.
Templates: `configs/sensor-templates/*.tmpl` (editable on the API host,
`SENSOR_CONFIG_TEMPLATES_DIR`); the built-in fallbacks in
`internal/app/sensor/config_templates_builtin.go` are generated from them
(`go generate ./internal/app/sensor/`, a test keeps them identical).

Every snippet works as pasted for the release it pins (tests run `bash -n` on
the shell ones and parse the YAML ones; `docker compose config` accepts the
compose file):

- **Image** `SENSOR_IMAGE` (default `ghcr.io/openctemio/sensor`) with the tag
  `SENSOR_LATEST_VERSION`, never `latest`. The response's `image` says which.
- **URL** `SENSOR_PUBLIC_API_URL`, else `APP_URL` (`api_url` in the response).
- **Key** only when the caller passes the freshly issued key in
  `X-Sensor-API-Key` (validated: key characters only, it lands in a shell
  line); otherwise the snippets read `$OPENCTEM_API_KEY` and stop with a clear
  message when it is unset. Compose keeps the key in `.env`, Kubernetes and
  Helm in a Secret. The response is `Cache-Control: no-store`.
- **CA** `SENSOR_CA_CERT_FILE`: the platform's private CA, e.g. the root the
  built-in gateway exports in TLS mode internal (`deploy/docker-compose.yml`
  mounts the export directory into the API read-only and sets
  `/ca/openctem-root-ca.crt`). Only X.509 `CERTIFICATE` blocks are used (a
  key in the file never leaks); the response carries `ca_certificate` and
  `ca_fingerprint_sha256`. The snippets install it under
  `/etc/openctem/certs` and set `SSL_CERT_DIR`, which adds it to the system
  roots (the sensor still verifies public scan targets). Unset or unreadable:
  the snippets assume a publicly trusted certificate.
- **Outbox** a named volume / PVC at `/var/lib/openctem/outbox`, so results
  survive a restart or an outage.
- **State** (daemon sensors) a named volume / PVC at `/var/lib/openctem/state`:
  the sensor (sdk-go v0.12+) keeps the API key it renews on its own there, so a
  recreated container comes back with the renewed key instead of the
  installed one, which the renewal retired. Back it up like a credential.
- **Content** (daemon sensors) a named volume / PVC (5Gi) at
  `/var/lib/openctem/content`: the scanner content cache (trivy DB, nuclei
  templates, semgrep rules), so a new container does not download it again.
  Disposable, kept apart from the state. The Helm snippet sets
  `sensor.state.persistence.enabled=true` and
  `sensor.content.persistence.enabled=true`.
- **Tools** `SENSOR_TOOLS` from the sensor's tools; names other than
  `[a-z0-9_-]` are dropped. The name becomes a slug.

## Key use and cloned identities

RFC-032 Phase 0 (`docs/rfcs/RFC-032-sensor-enrollment-and-identity.md`
§10.2): signals about a sensor key, before key-bound identity (Phase 1)
replaces bearer keys.

- **Where the key is used from.** Every authenticated request (v1 and v2,
  inline key or a `sensor_api_keys` row) records the client address under the
  trusted-proxy rule (`SERVER_TRUSTED_PROXIES`; a forwarding header from an
  untrusted peer is ignored) and the time: `sensors.api_key_last_used_ip` /
  `_at` (migration 000256), and `sensor_api_keys.last_used_ip` for a renewed
  key. A request from another address than the previous one writes a
  `key_ip_changed` event on the timeline (folded and capped like every
  event). The response carries `key_last_used_at` and `key_last_used_ip`.
- **Cloned identity.** The SDK (sdk-go v0.12+) sends a random per-process
  `instance_id` on every heartbeat; older SDKs are observed by hostname
  (`host:<hash>`). A restart replaces the instance once; a key running in two
  places makes the instances alternate. When replaced instances come back
  three times within 15 minutes (`pkg/domain/sensor/identity.go`) the sensor
  is flagged: `identity_cloned_at`, health reason `identity_cloned`
  (critical), one `identity_cloned` event and one `sensor.identity_cloned`
  audit entry (severity high). Steady-state heartbeats cost nothing (the
  instance is compared with the row already read); a change is applied under
  a row lock. Regenerating the key clears the flag. The sensor is not
  quarantined automatically in Phase 0.
- **Key-hash pepper.** Keys are stored as HMAC-SHA256 under
  `SENSOR_KEY_PEPPER`, or, when unset, a pepper derived from
  `APP_ENCRYPTION_KEY` with HKDF-SHA256 (label
  `openctem/sensor-api-key-pepper/v1`), so the MAC key is never the
  encryption key. Hashes stored under earlier peppers keep verifying: the
  encryption key itself (before this release), the derived pepper (after
  `SENSOR_KEY_PEPPER` is set), `SENSOR_KEY_PEPPER_PREVIOUS` (comma-separated,
  for replacing an explicit pepper) and plain SHA-256 (before any pepper).
  New, regenerated and renewed keys are stored under the current pepper.
  Rolling the API back below this release makes keys issued after it
  unknown to the older server.
- **Secrets in `scanner_config`.** Scan responses carry
  `scanner_config_warnings` (`path`, `reason`: `key_name`, `known_format`,
  `high_entropy`) for values that look like credentials
  (`pkg/domain/scan/config_secrets.go`). The config travels to the sensor in
  clear inside every command; the warning never blocks a save and never
  echoes the value.
  Callers without `scans:write` (viewers, custom read-only roles) get exactly
  the warned values replaced by `********` (`scan.RedactConfigSecrets`,
  `pkg/domain/scan/config_redact.go`) in every user-facing response that
  carries the config: `GET /scans`, `GET /scans/{id}`,
  `GET /scans/{id}/export`, and the `payload` of `GET /commands` and
  `GET /commands/{id}` (which embeds the config as `scanner_config`,
  `config` and `context.scanner_config`). The structure, the non-secret
  values and `scanner_config_warnings` stay. Owners, admins and members with
  `scans:write` see the real values, because they edit them. Sensors claim
  the stored command and are unaffected. As a guard, a `PUT /scans/{id}`
  whose `scanner_config` has `********` where the stored value would be
  masked keeps the stored value instead of saving the mask. An export taken
  by a reader holds the masks and must have its secrets re-entered before it
  is imported.

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

**Text caps on every ingest path** (v1 CTIS, v2 segments, SARIF and the
other converted formats; `internal/app/ingest/text_caps.go`, RFC-040 §5.4).
Before anything is stored or fingerprinted, `Service.Ingest` cuts oversized
finding text to a cap, ending it with `…[truncated]`, and makes it valid
UTF-8: title and rule name 500 characters (their column size), category 255,
message 8 Ki, description 32 Ki, evidence 64 Ki, snippets and remediation
text 16 Ki, misconfiguration expected/actual/cause/query 4 Ki. Lists are cut
to a count and each item to a length: references 100 × 2 Ki (finding and
remediation), tags 50 × 100, vulnerability classes and subcategories
50 × 200, remediation steps 50 × 2 Ki. A cut never refuses the report or
the finding (a title over 500 characters used to fail that finding); the
number of capped values is logged per report.

### Processing

The ingest worker runs v2 jobs whatever `INGEST_MODE` is
(`internal/app/ingest/v2_jobs.go`, `v2.go`).

**The sensor is re-read before a queued job runs** (v1 async jobs and v2
segment and commit jobs; `internal/app/ingest/queued_sensor.go`, RFC-040
§5.2). The sensor was authenticated when the report was accepted, but it may
have been revoked, disabled or deleted while the report waited. Its work is
then dropped: nothing is ingested, a v2 report goes to `failed`, the job
completes (no retry) with `{"dropped": true, "reason": …}`, and the tenant's
audit log gets an `ingest.failed` entry with result `denied`. A v1 job is
ingested as the stored sensor, not as a minimal sensor rebuilt from the job.
A failed lookup is retried; without a sensor repository every job fails
(fail closed).

Each segment runs through the v1 pipeline with the v2 options:

- **No fallback asset.** A finding binds to the asset its `asset_ref` names
  in its own segment, or to the segment's only asset when it names none.
  Anything else is rejected as an item (`asset_unresolved`, with a JSON
  pointer); no asset is made up from metadata.
- **No global catalog writes.** Findings link to CVE catalog rows that
  exist; the sensor's CVE text stays on the tenant's finding. The catalog is
  written by trusted feeds only.
- **Default-branch auto-resolve needs a proven run** (research 18 F3). Only a
  protocol v2 run **bound to a command** closes repository findings; it is
  evaluated per command (`evaluateRepoCoverage`) at the report's commit and
  again when the command completes. It qualifies only if the command
  completed with exit code 0, every report of the run completed with nothing
  rejected, quarantined or in error, every report is an **explicitly** `full`
  scan of a default branch (a missing `coverage_type` is not full), and all
  reports name one tool the sensors declare. Candidates are open
  default-branch findings of that tool on the assets the run touched **and**
  the command covers, not reported by the run, and last seen by a report of
  the same tool **under the same scan profile** (the stand-in for "same
  ruleset" until runs carry a ruleset digest; a finding last seen under
  another profile, by a v1 report or by an upload is never a candidate). The
  blinding guard holds a close of more than `SENSOR_V2_BLINDING_MIN_FINDINGS`
  (100) and more than `SENSOR_V2_BLINDING_RATIO` (50 %) of the open findings
  of that tool on those assets (`auto_resolve: held`). A report without a
  command (CI, collector, `warn` mode), a tenant upload and any protocol v1
  report never close a finding (owner decision O11); the per-branch
  occurrence sweep is unchanged.
- **Coverage-scoped auto-resolve (non-repository findings).** The
  default-branch auto-resolve above only covers repository findings, so a host or
  web finding was never closed by a later scan. A scan command is evaluated
  when it is `completed` AND every report filed under it is `completed`
  (checked from both ends: command completion and report finalize). It
  qualifies only if the command exited 0, every report has no rejected or
  quarantined items and declares `coverage_type: full` (an absent value is
  not full, CTIS spec 4.5; sensors on sdk-go with openctemio/sdk-go#150
  always send it), all reports name one
  tool the sensor declares, and the reports touched at least one asset. The
  candidates are open findings of that tool on the touched assets, with no
  branch, not reported by this run, and last seen by a v2 run of the same
  scan profile (a v1 or imported sighting is never a candidate). The blinding
  guard applies. `INGEST_COVERAGE_AUTO_RESOLVE` = `dry_run` (default: log,
  `findings_coverage_auto_resolve_total{mode,result}` and an
  `ingest.coverage_auto_resolve_dry_run` audit entry listing the findings, no
  state change), `enforce` (closes them as `auto_fixed`/`scan_verified`,
  audited as `ingest.coverage_auto_resolved`) or `off`.
- An uncommitted report expires 60 minutes after its last segment; its
  upserts stay and it never resolves anything. A segment's outcome is stored
  under its number, so a retried segment is never counted twice. Payloads
  are dropped once the report completes.

**Finding tags** (every ingest path, v1 and v2). A new finding stores the
tags its report sent, empty and repeated ones dropped, at most
`vulnerability.MaxFindingTags` (50, the limit of `PUT /findings/{id}/tags`).
A re-sighting of an existing fingerprint **merges**: the stored tags stay
first and in order (a user may have set them), new ones are appended, and
the list stops at 50. The enrich path (`Finding.EnrichFrom`) and the
upsert's `ON CONFLICT` apply the same rule, so a scanner can add tags but
never remove one. Only the tags API replaces the list.

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
| `INGEST_COVERAGE_AUTO_RESOLVE` | `dry_run` | Coverage-scoped auto-resolve of non-repository findings: `off`, `dry_run` or `enforce`. Keep `dry_run`: enforcement is postponed until the closure evaluator ships (owner decision D-22, research 18 P2); this path cannot see template, port or authentication coverage. |
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
`protocol_client` and `protocol_seen_at` (migration 000248), in the
heartbeat update that already runs. `GET /api/v1/sensors` and
`GET /api/v1/sensors/{id}` return

```json
"protocol": {"version": 1, "user_agent": "openctem-sdk-go/0.8.1", "seen_at": "2026-10-02T09:00:00Z", "deprecated": true}
```

or `null` before the first heartbeat that recorded it. A sensor on sdk-go
0.8.x (v2 results, v1 heartbeat) reads `1`: it still needs the upgrade.
`sensor_protocol_requests_total{protocol, route}` counts every sensor request
by protocol and route name (closed sets).

## Sensor-reported capabilities

[RFC-029 §4.3.1](../rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md).
The heartbeat (v1 and v2) can carry what the sensor really has: `tools`
(`[{name, kind, version, installed, capabilities, content}]`), `capabilities`,
`max_concurrent_jobs`, `os` and `arch`. Each tool's `capabilities` (sdk-go
v0.13+) says what that tool serves besides its name (`nuclei` → `dast`,
`validate:nuclei`), so the flat list can be traced to a tool; `kind` is
`scanner` or `collector`. Both are sanitized like the flat list (known names
only, at most 32 per tool) and kept in `reported_tools`. The sensor's report is the truth. The administrator's `tools`,
`capabilities` and `max_concurrent_jobs` on the sensor are **limits** that can
only narrow it:

- effective tools = reported installed tools ∩ `tools` (empty `tools`: all reported)
- effective capabilities = reported ∩ `capabilities` (likewise)
- effective concurrency = the smallest of the reported ceiling
  (`max_concurrent_jobs`), the administrator's `max_concurrent_jobs` and the
  reported slots (`capacity.slots_total`, see "Load, capacity and release")
  that is set (RFC-033 §6.1)
- not reported (old SDK): the administrator's values, unchanged, except that
  **dispatch sends such a sensor no tool**: a declared tool is unverified (see below)

Storage (migration 000253): `reported_tools` (jsonb), `reported_tool_names`,
`reported_capabilities`, `reported_max_jobs`, `reported_os`, `reported_arch`,
`reported_at`, and the generated columns `effective_tools`,
`effective_capabilities`, `effective_max_jobs`, built with
`sensor_effective_list(declared, reported)` and (000257)
`sensor_effective_max_jobs(admin, reported, capacity)`. Every dispatch query reads the
`effective_*` columns: selector, `ClaimJob`, tool and capability
availability, list filters and platform capacity. The command poll's capability
gate and the API use `Sensor.EffectiveCapabilities()` and the other
`Effective*` methods (`pkg/domain/sensor/reported.go`).
`sensor_reported_caps_db_test.go` (postgres) checks that the columns and the
methods agree across a matrix of inputs.

RFC-030's tool gate on the command poll, the claim, the doorbell count and
the zone predicate (`sensorDispatchTools` in `command_repository.go`) reads
the sensor's **verified** tools: `effective_tools` when the sensor reported
its tools, none when it never did. The selector, `FindAvailableWithTool`,
`HasSensorForTool` (the trigger's availability check) and
`GetAvailableToolsForTenant` use the same expression. A command that names a
tool reaches only sensors whose own probe found it installed; a tool the
administrator merely declared on a sensor that never reported gets no work
(it used to, and failed with "scanner not found"). Tool-less and
capability-scoped commands are unaffected.

**Capacity vs slots** (Kubernetes' `capacity` vs `allocatable`). The reported
`max_concurrent_jobs` is the sensor **operator's ceiling** (`SENSOR_MAX_JOBS`),
sent only when one is set; `capacity.slots_total` is what the sensor can run
**now**, sized by the SDK from its CPU, memory and tools' learned cost (at
most the ceiling). sdk-go before v0.13 sent its resource manager's upper bound
(64) as `max_concurrent_jobs` when no ceiling was set; the slots bound keeps
such a sensor from being counted at 64 or at an administrator limit above
what it runs. The last reported slots count however old they are (the column
cannot see the clock); a stale report's `slots_free` is ignored (below).

Ingest (`SensorService.UpdateHeartbeat` → `sanitizeReport`): one catalog
lookup (`KnownCapabilityNames`: active platform tools and the tenant's own,
plus the capability registry), then `CapabilityReportInput.Sanitize`. Unknown
or malformed names are dropped, lists are capped at 64, versions and the
platform are reduced to safe tokens, and concurrency is clamped to 1..100. A
report part that is absent leaves the stored part alone. If the catalog cannot
be read, the report is skipped and the heartbeat still succeeds.

`GET /api/v1/sensors[/{id}]` returns `reported` (null before the first
report), `effective`, and `capability_mismatch` (`tools_not_installed`,
`capabilities_not_reported`; omitted when there is nothing to show). `PUT` with `tools: []` / `capabilities: []` removes the
limit.

## Sensor manifest

[RFC-033](../rfcs/RFC-033-sensor-manifest.md). A manifest is what a sensor
*is*, as opposed to its load. It contains:

- build, platform and resources
- the operator's concurrency ceiling and the sensor-wide capabilities
- its tools, each with kind, version, installed state, capabilities, target
  types and content versions

It is registered once and again on change. Heartbeats keep carrying the load.

**Wire (protocol v2, feature `manifest`).**

- `PUT /api/v2/sensor/manifest`:
  - body: a JSON document, `schema: 1`, at most 256 KiB
  - answers `{manifest_digest, changed, accepted: {tools, capabilities},
    ignored: [{path, value, reason}]}`
  - unknown members, tools (not in the catalog) and capabilities (not in the
    registry) are ignored and listed, never an error
  - problems: 413 `content-too-large`, 422 `manifest-invalid`,
    422 `manifest-schema-unsupported`, 503 `unavailable` (catalog unreadable,
    retry)
- The digest is `sha256:` over the canonical JSON of the document as received
  (sorted members, no whitespace, no HTML escaping). The platform computes it
  and the sensor echoes it.
- The heartbeat's optional `manifest_digest`: when it is not the current one,
  the answer adds the action `send_manifest`. This goes only to sensors that
  send a digest; deployed sensors ignore unknown actions anyway.

**Processing** (`SensorService.RegisterManifest`):

1. Parse leniently and digest.
2. Turn it into a capability report:
   - flat capabilities = installed tools' names + their capabilities +
     sensor-wide ones, the SDK registry's rule
   - sanitize it with the heartbeat's catalog lookup
3. An unchanged digest only touches the version's `last_seen_at`.
4. A new one is stored in one transaction:
   - a `sensor_manifests` row; a sensor going back to an earlier manifest
     makes that row current again
   - `sensors.manifest_digest`, `manifest_at`, `manifest_source`
   - the `reported_*` projection. A manifest is a complete statement, so its
     ceiling and platform replace the stored ones, NULL included.
5. Old versions are pruned in the same transaction: the newest 50 are kept,
   plus any seen in the last 90 days.
6. The diff goes to the activity timeline with the existing event types,
   each with `manifest_digest` and `previous_manifest_digest` in its details.

**Derived manifests.** For a heartbeat without `manifest_digest` that carries
tools (protocol v1, older SDKs), the platform builds the manifest from the
sanitized report. Its sensor-wide capabilities are the flat ones no installed
tool provides. The platform stores it with `source = heartbeat` only when its
digest differs from the current one. Every sensor therefore gets a version
history, and a steady heartbeat writes nothing extra. The comparison uses the
digest in the row the heartbeat already reads.

**Phase 2** (RFC-033 §6.12, owner decisions O1–O4):

- **Policy echo.** The PUT answer and `GET /api/v2/sensor/manifest` carry
  `policy {allowed_tools, allowed_capabilities, max_jobs}`, the sensor's
  effective values, and `heartbeat {omit_inventory}`. GET answers 404
  `manifest-not-found` before the first registration. The SDK re-reads it
  when the heartbeat's `config_version` changes, and fails a command whose
  tool (payload `scanner`, else `preferred_tool`) is not allowed, with
  `tool-not-allowed`.
- **Slim heartbeats.** While a heartbeat echoes the acknowledged digest and
  the answer said `omit_inventory: true`, it leaves `tools`, `capabilities`
  and `max_concurrent_jobs` out. It sends `content: [{tool, name, version,
  …timestamps, error}]` instead, which `withSlimContent` merges into the
  stored tools, so RFC-031 content health keeps working. A slim heartbeat
  never clears the ceiling.
- **Kill switch.** `SENSOR_SLIM_HEARTBEAT=false` (default `true`) makes
  answers say `omit_inventory: false`, and a slim heartbeat gets
  `send_manifest`, so the sensor goes back to full heartbeats.
- **Activity.** A sensor-registered manifest that replaces another records
  one `manifest_changed` event (`updates`). Its details carry `diff` (tools
  added and removed, versions, installed, per-tool and sensor-wide
  capabilities, other members) and both digests. Content versions keep
  `content_updated`. Heartbeat-derived manifests keep the heartbeat's diff
  events. A heartbeat that carries `manifest_digest` writes no
  `tools_changed` or `capacity_changed`: for a registering sensor, the
  manifest records those. No re-approval (O1).
- **Size.** On the official sensor, a slim heartbeat is about 2.1 KB against
  2.6 KB for a full one. The load report (resources, per-tool cost, queue)
  makes up the rest and stays.

**Reads.**

- `GET /api/v1/sensors/{id}/manifest`: the current version, or 404 when there
  is none yet.
- `GET /api/v1/sensors/{id}/manifests?limit=`: history, most recently current
  first. Both need `sensors:read` and are tenant-scoped.
- The sensor response carries `manifest_digest`, `manifest_at` and
  `manifest_source`.

Code: `pkg/domain/sensor/manifest.go`, `internal/app/sensor/manifest.go`,
`internal/infra/postgres/sensor_manifest.go`,
`internal/infra/http/handler/sensor_control_v2_handler.go` (`PutManifest`),
`sensor_manifest_handler.go`. Migration 000258. Tests:
`routes/sensor_manifest_db_test.go`, `sensor/manifest_test.go`.

## Collector sensors

A sensor of type `collector` (`sensor.SensorTypeCollector`) pulls asset
inventory from an external system and submits it as CTIS assets. It runs
its collections on its own schedule: it takes no dispatched scans. The
reference implementation is the OpenCTEM Asset Collector
([github.com/openctemio/asset-collector](https://github.com/openctemio/asset-collector),
image `ghcr.io/openctemio/asset-collector`, formerly `asset-inventory`).

- **Type and key.** An administrator creates the sensor with type
  `collector` (a rotated key gets `sensor.CollectorScopes()`). Until
  enrollment ships ([RFC-032](../rfcs/RFC-032-sensor-enrollment-and-identity.md)),
  the collector uses an `octs_` key and renews it like any other sensor.
- **Protocol.** It uses protocol v2 through sdk-go `pkg/sensorkit` (hello,
  heartbeat with control block, manifest, results ingest, durable outbox,
  key renewal), with commands off. Reports go to
  `PUT /api/v2/sensor/results/{report_id}` (unbound to a command) with
  `metadata.source_type = "collector"` and the collector type as
  `tool.name`.
- **Tools.** It reports one tool per configured collector type, of kind
  `collector` (`sensor.ToolKindCollector`): `gcp-dns`, `vcenter`, `ldap`,
  `splunk` and `prtg`. The platform keeps only tool names in its catalog, so
  these are in it (migration 000265, category `inventory`, "Asset
  Collectors").
- **Not scannable.** Their catalog rows carry `metadata.kind =
  "collector"` (`tool.KindCollector`). Scan creation and trigger refuse such
  a tool, as a single scanner or as a pipeline step (`tool.Tool.IsCollector`,
  error code `TOOL_NOT_SCANNER` at trigger), because nothing would ever
  claim the job.
- **Adding a collector type.** Add a catalog row with `metadata.kind =
  "collector"` in a migration, then report it from the collector.

## Result binding and the results quarantine (RFC-040)

A report changes existing assets, reopens findings a person resolved and
auto-resolves only when it names a command assigned to the sensor and open
(the v2 `commands/{command_id}/results/...` path, or `X-OpenCTEM-Command-ID`
on v1), and only on the assets that command's targets cover. Collector and
runner reports without a command are applied with limits; other roles' are
applied with limits (tenant mode `warn`, every tenant that existed at
upgrade) or held for review (`quarantine`, new tenants). Rule, response
codes, compatibility and the review API:
[sensor-result-binding.md](sensor-result-binding.md).

## Scanner content

[RFC-031](../rfcs/RFC-031-managed-sensor-updates.md). A tool's binary is
pinned in the sensor image; its **content** is not: trivy's vulnerability
database, the nuclei templates, the semgrep rules. A sensor with a content
manager refreshes, verifies and atomically swaps that content itself, and
reports it on the heartbeat inside its tool inventory:

```json
"tools": [{"name": "trivy", "version": "0.69.3", "installed": true,
  "content": [{"name": "trivy-db", "version": "2026-10-02T01:05:41Z",
    "updated_at": "2026-10-02T01:05:41Z", "fetched_at": "2026-10-02T04:59:26Z",
    "checked_at": "2026-10-02T05:30:00Z",
    "source": "mirror.gcr.io/aquasec/trivy-db:2", "digest": "sha256:3b16…",
    "managed": true, "error": ""}]}]
```

Content names: `trivy-db`, `trivy-java-db`, `nuclei-templates`,
`semgrep-rules`. `managed: false` is content the tool fetches by itself (semgrep
`--config auto`): shown, never flagged stale.

**Storage.** Inside `sensors.reported_tools` (migration 000253): each tool's
`content` member, sanitized by `CapabilityReportInput.Sanitize` →
`sanitizeToolContent` (names `[a-z0-9-]`, at most 8 per tool, version 128 /
source 256 / error 256 bytes, a digest only when `sha256:<hex>`, timestamps no
later than a day ahead). No column of its own.

**Policy** (`sensor_content_policies`, migration 000253, one row per tenant):
`refresh_interval_hours`, and per content `max_age_hours`, a pinned `version`
(an OCI digest `sha256:…` for a database, a release tag for templates) and, for
`semgrep-rules`, `rulesets` (`p/default`). 0 or absent = the platform default
(trivy-db 48 h, trivy-java-db 168 h, nuclei-templates 336 h, semgrep-rules
168 h, refresh every 6 h). **The policy never names a content source**
(registry, mirror, URL, directory): sources are the sensor host's
configuration, so a compromised platform cannot point a fleet at other
content. Sensors receive the policy on `refresh_content` commands and keep it.

| Route | Permission | Does |
|---|---|---|
| `GET /api/v1/sensors/content-policy` | `sensors:read` | `{policy, defaults, updated_at, updated_by}` (policy with defaults filled) |
| `PUT /api/v1/sensors/content-policy` | `sensors:write` | `{policy, apply_now}`; `apply_now` queues a refresh (not forced) carrying the policy to every eligible sensor and returns `commands_created`, `skipped` |
| `POST /api/v1/sensors/{id}/content/refresh` | `sensors:write` | `{content?, force? (default true)}` → `202 {command_id, already_pending}`; `409` when the sensor manages no content or is disabled/revoked; `404` for another tenant's sensor |
| `POST /api/v1/sensors/content/refresh` | `sensors:write` | the same for every eligible sensor → `{commands_created, skipped}` |

A refresh is a `refresh_content` command pinned to the sensor, expiring after
24 h, payload `{content, force, policy}` (sdk-go `core.RefreshContentRequest`).
At most one is open (pending, acknowledged or running) per sensor: a second
request returns it (`already_pending`). Eligible = active and reporting at
least one `managed` content item; an older sensor would never claim the type,
so it is not sent one. Policy updates and refresh requests are audited
(`sensor.content_policy_updated`, `sensor.content_refresh_requested`).

**Read model.** Every sensor response has `content` (never null): per tool and
content the reported fields (including `checked_at`) plus `age_seconds`, `max_age_hours`, `stale`,
`pinned_version`, `pin_mismatch`, judged against the tenant's policy, and
`content_refresh_supported`.

**Health reasons** (`pkg/domain/sensor/content_health.go`), both `warning`, so
an online sensor becomes `degraded`:

- `content_stale`: managed content older than its limit **and** not
  confirmed current within it (`checked_at`: when the sensor last confirmed
  with its source that this is still the newest or pinned version; the same
  rule as sdk-go `ContentInfo.Stale`), or none installed yet. A template set
  whose newest release is 15 days old is not stale while the sensor keeps
  confirming it. "The nuclei templates are 15d old (limit 14d). The sensor has
  not confirmed a newer version for 15d. The last refresh failed: …".
- `content_refresh_failed`: the last refresh failed but the content is still
  within its limit: "Refreshing the nuclei templates failed: checksum
  mismatch. Scans use v10.4.8."

**Per-scan provenance.** The sensor stamps the content a scan used on the
report's `tool.properties.content` (CTIS `properties` is free-form, no schema
change). For protocol v2 the tool is part of the report header, stored
verbatim in `ingest_reports.header`; findings carry the report id as
`scan_id`. Protocol v1 ingest keeps no report header.

## Load, capacity and release (RFC-030)

The heartbeat may carry the sensor's **load report**, computed by the SDK
(feature `load`): `resources` (cgroup-aware CPU cores and use, memory limit
and available, load1, free disk), `capacity` (`slots_total`, `slots_free`,
`active_jobs`, `per_tool` cost and throughput) and `queue` (the SDK's local
work queue). The API clamps it and stores the latest snapshot
(`sensors.reported_resources`, `reported_capacity`, `reported_queue`,
`load_reported_at`; migration 000254); `GET /api/v1/sensors/{id}` shows it as
`load` with `fresh`.

Capacity is counted by the server: `current_jobs` in the API is the number
of commands the sensor holds (acknowledged or running), and
`available_slots` is `effective max jobs − current_jobs`, no more than a
fresh (≤ 3 min) `capacity.slots_free`. The command poll (v1 and v2) never
offers more scan commands than that; selection skips sensors with no free
slot and prefers the most free slots, then the highest reported throughput
for the tool. `sensors.current_jobs` (never written) is no longer read.

The poll orders commands fairly (RFC-046 §11): by priority class, a command
moving up one class per 30 minutes waited (never into `critical`), then
round-robin across runs (the first pending command of every run before the
second of any), then age.

**Claim-N** (feature `capacity`, RFC-030 §5.9): a v2 sensor that names
`capacity` in `X-OpenCTEM-Sensor-Features` gets `GET /api/v2/sensor/commands`
already claimed for it: acknowledged, lease and epoch set, in one
`UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED)` that re-checks the
tenant, pinning, zone, tool and capability gates. Scans are capped at the
sensor's effective max jobs minus the scans it holds, counted from the
commands, and at a fresh reported `slots_free`. Its later `claim` of each
command is a replay (`200`). Without the feature the poll only lists, as
before.

A sensor hands a command it holds back with
`POST /api/v2/sensor/commands/{id}/release` (feature `release`): the
command returns to `pending`, unpinned, zone kept, so another sensor takes
it at once (a draining sensor). See RFC-030 §5.8.1 and §5.12.

### Command leases (RFC-035 D6)

A sensor holds every command it claims under a **lease** (migration 000260:
`commands.lease_epoch`, `commands.lease_expires_at`).

- **Claim.** A claim starts a new lease epoch (`lease_epoch + 1`) and a lease
  of `SENSOR_COMMAND_LEASE` (default 3 min, clamped to 1–30 min). That is
  longer than a silent sensor takes to go `stale` and `offline` at the
  idle interval ("Fleet health"), so a sensor whose heartbeats are only late
  keeps its work.
- **Renewal.**
  - Every accepted heartbeat (v1 and v2) renews the leases of the commands
    the sensor lists in `running`.
  - An SDK that sends the load report (`queue`) always lists what it holds,
    leaving the list out when it holds nothing.
  - A sensor that sends no load report has every command it holds renewed:
    older SDKs keep their work.
  - `start` renews the lease too.
- **Re-queue.** The job-recovery controller (every 60 s) takes back every
  tenant command whose lease ran out: `pending`, unpinned, zone kept,
  `dispatch_attempts + 1`, `error_message` saying why.
  `fail_exhausted_commands` still ends a command after the maximum number of
  attempts. A dead sensor's running scans are back in the queue within about
  lease + 60 s, not at the 1 h run timeout (RFC-035 B5).
- **Revocation** (RFC-040 §5.2). Revoking or disabling a sensor
  (`POST /sensors/{id}/revoke`, `/deactivate`, or `PUT /sensors/{id}` with that
  status) takes back every tenant command it holds (`acknowledged` or
  `running`) in the same request, not at lease expiry
  (`CommandRepository.ReleaseHeldBySensor`):
  - **Routed scan work** (type `scan` with a `pipeline_run_id`, the same rule
    as the release of pending work pinned to an unavailable sensor) goes
    back to `pending`, unpinned, zone kept, without a dispatch attempt, with
    `re-queued: the sensor holding it was revoked` (or `disabled`).
  - **Anything else** was addressed to that sensor only (`config_update`, a
    scan sent to it by id) and is `failed`, with `failed: the sensor it was
    addressed to was revoked while holding it` (or `disabled`).
  - The lease is cleared, so the fence below refuses the old holder's late
    `start`, `complete` and `fail`; the next claim starts a new epoch.
  - One `sensor.commands_released` audit entry (severity high) lists the
    re-queued and failed command ids, under the administrator who acted, or
    `system`.
  - The release runs after the status change is stored. If it fails it is
    logged, and the lease reaper takes the commands back when their lease
    runs out.
- **Fencing.**
  - **Guarded writes.** `start`, `complete` and `fail` from a sensor are
    guarded UPDATEs. They apply only if the command is still held by that
    sensor, in the state and lease epoch it was read in.
  - **Lost commands.** A sensor whose command was re-queued, or claimed again
    by another sensor, gets `invalid-transition` (state `pending`) or
    `command-not-found`. Its result is never stored: **no duplicate
    completion**.
  - **Epoch header.** v2 commands carry `lease_epoch` and
    `lease_expires_at`. A sensor may send the epoch back in
    `X-OpenCTEM-Lease-Epoch` on `complete` and `fail`; a different current
    epoch refuses the change.
  - **Duplicate ids.** The SDK never runs the same command id twice at once.
- **Legacy reaper.** The 10-minute reaper for `acknowledged` commands
  (`recover_stuck_tenant_commands`) only handles commands without a lease
  (claimed before migration 000260).

## Sensor-local policy (RFC-040 §5.7)

> **Version requirement.** Enforcement is in sdk-go#140 and sensor#119, merged
> after sensor v0.8.0. Sensor v0.8.0 and older ignore `SENSOR_LOCAL_POLICY`,
> the policy file and the kill-switch file, and report no `local_policy`
> (the page shows `unknown`). The install snippets mount the file anyway; it
> takes effect once the sensor runs a release later than v0.8.0.

The owner of the scanned network installs a read-only policy file on the
sensor host (`/etc/openctem/sensor-policy.yaml`, `SENSOR_LOCAL_POLICY`; keys
and semantics in the sensor repository, `docs/LOCAL_POLICY.md`). The sensor
(sdk-go `core.LocalPolicy`) refuses every job outside it, even one the
platform sent; the platform cannot change it. The platform side only shows it
and narrows dispatch:

- **Hello feature `local_policy`.** Listed whenever heartbeats are served.
  SDKs that see it add `local_policy` to the heartbeat and the manifest:
  `state` (`enforced`, `absent`), `source`, `digest`, a `summary` (counts of
  allow and deny entries, private yes/no, ports, tools, job types, the
  custom-template and interactsh switches, rate caps; never the ranges),
  `kill_switch` and `warnings`. Older SDKs send nothing.
- **Storage.** `sensors.reported_local_policy` (JSONB, migration 000298) and
  `local_policy_reported_at`, sanitized at ingest
  (`sensor.SanitizeLocalPolicyReport`: known states only, digest format,
  bounded lists and warnings, control and bidi characters removed). A slim
  heartbeat carries only state, digest and kill switch; the stored summary of
  the same policy is kept (`MergeLocalPolicyReport`). The manifest's report
  is stored too (it has the summary), keeping the heartbeat's live kill
  switch.
- **Sensor page.** `GET /sensors/{id}` returns `local_policy` with the display
  state `enforced`, `absent`, `paused` (kill switch engaged) or `unknown`
  (never reported); the detail sheet's Local policy section shows it with the
  digest and summary.
- **Timeline.** `local_policy_changed` (updates) when the state, digest or
  kill switch changes.
- **Refusals (detection A11).** A job the sensor refused fails with
  `refused by local policy: <rule>: <detail>`. `command.Service.Fail` hands
  every failure to `SensorService.ObserveLocalPolicyRefusal`, which records a
  `job_refused_local_policy` job event (identical rules fold within the event
  window) and, once per folded burst, the audit action
  `sensor.job_refused_local_policy` (severity high).
- **Structured refusal and re-queue** (research/25 §3.6, D8; migration
  001019). Hello feature `refusal`: v2 `POST /commands/{id}/fail` accepts
  `refusal: {layer, rule, detail}` (layer from a closed set: `builtin`,
  `local`, `managed`, `scope`, `platform_tool_gate`; sanitized like the
  report). Without it a reason starting `refused by local policy: ` still
  counts (older SDKs, protocol v1). For **routed work** (a scan command with a
  `pipeline_run_id`, the work the platform chose a sensor for; the rule the
  lease and release paths use) the command is re-queued instead of failed:
  pending, unpinned, zone kept, one more dispatch attempt, the refusal
  appended to `commands.refusals` and the sensor to `commands.refused_by`,
  which the poll, claim, claim-by-id and doorbell predicates exclude. It is
  re-queued only while another sensor that could claim it (same tenant,
  dispatchable, same zone, the tool) has a report that `sensor.Accepts` the
  job; otherwise, or at the third refusal (`command.MaxRefusals`), it fails
  with the aggregated reasons, the last refusal first so its prefix stays
  parseable. A re-queued command fires no pipeline failure. Commands a person
  addressed to one sensor fail as before. A sensor that retries the same fail
  after the re-queue gets a 409 (the command is no longer its own).
- **Tenant switch.** Security settings
  `require_sensor_local_policy_for_private_targets` (default off, owner
  decision Q3 (a)). On, a sensor that does not enforce a policy (absent,
  unknown, or paused) neither sees in its poll nor can claim a command whose
  payload names a private, loopback, link-local or CGNAT address, a range
  overlapping one, or a private-namespace host name (`.local`, `.internal`,
  `.lan`, `.corp`, `.home.arpa`, ...); the claim answers "claimed" so the
  command waits for a qualifying sensor. Names that resolve to private
  addresses in public DNS are not detected here; the sensor's own policy
  covers them. An unreadable tenant setting withholds (fail closed).
- **Dispatch pre-check** (research/25 §3.6). One function,
  `sensor.Accepts(report, job, options)` (`pkg/domain/sensor/accepts.go`),
  decides whether a sensor's last report would refuse a job, reading the
  payload as the sensor's admission check does (`sensor.JobOf`: tool from
  `scanner`/`scanner_name`/`preferred_tool`, `config.allow_interactsh`,
  `custom_templates`, `config.ports`, literal private addresses). It mirrors
  the summary: kill switch (withholds everything), `checks.allow`,
  `tools.allow`, `allow_custom_templates`, `allow_interactsh`, `ports.allow`
  (exact lists only; named lists such as `top-100` are left to the sensor),
  `targets.allow_private` (literal RFC 1918 / fc00::/7 targets only), and the
  tenant switch above (layer `managed`). Allow and deny ranges are reported as
  counts, so they are left to the sensor. A sensor without a report or
  without a policy accepts what the policy would decide (the absent policy
  allows both opt-ins, owner decision Q4 (a)). The same check runs in three
  places:
  - **poll and claim** (`command.Service.Poll`, `Claim`): commands the sensor
    would refuse are left pending for another sensor; the poll reads a wider
    candidate window so a refused queue head does not starve the sensor;
  - **claim by id** (`Acknowledge`): refused as "claimed"
    (`ErrSensorPolicyRefuses`), the command stays pending;
  - **scan trigger** (`scan.Service`, `policy_preflight.go`): a zone batch is
    pinned only to a zone sensor that accepts it (least loaded among those);
    a zone where no online sensor accepts reports its targets as not scanned,
    with the layer, rule and count ("allow_interactsh: refused by the local
    policy on 2 of 2 sensor(s) in scan zone "DMZ" ..."); targets outside
    zones are judged against the tenant's available sensors. When nothing is
    left to run the trigger is refused with `SENSOR_POLICY_REFUSED` (400) and
    no run or command is created. The zone-routing preview uses the same
    code.

  The pre-check only narrows: a report comes from the sensor, so a lying
  sensor can only withhold jobs from itself, and the sensor keeps enforcing
  its own policy on whatever it receives. Failures to read the sensor or the
  tenant setting withhold (fail closed).
- **Organization opt-ins, default off** (research/25 D3, D9). Security
  settings `allow_sensor_interactsh` and `allow_sensor_custom_templates`
  (`tenant.SecuritySettings`), off for existing and new organizations. The
  platform-side layer (`managed`) of the pre-check: with a switch off the
  platform sends no job that turns out-of-band callbacks on or carries custom
  templates, to any sensor, whatever its own policy allows. Sensors without a
  local policy (legacy ceiling: both on, Q4 (a)) are therefore safe from this
  release without a host change. Where it applies:
  - scan create and update refuse `allow_interactsh: true` (boolean or the
    string `"true"`) and a non-empty `custom_template_ids` with
    `SENSOR_OPT_IN_DISABLED` (400);
  - trigger of an existing scan: `allow_interactsh` is removed for that run
    (the stored scan is untouched; the run carries a warning), and a scan with
    custom templates is refused (running it without them would run the
    scanner's default set, wider than what the author chose);
  - `POST /api/v1/commands` refuses a scan payload asking for either (in
    `config`, `scanner_config` or `custom_templates`);
  - dispatch (`command.WithOptInPolicy`) withholds such commands from every
    sensor (claim by id: `ErrOptInDisabled`), the backstop for commands queued
    before the release; they expire. An unreadable setting withholds.

  Only an owner changes them (`PATCH /tenants/{tenant}/settings/security`).
  Turning one on is audited as `sensor.opt_in_changed` at critical severity
  and logged as alert `sensor_opt_in_enabled`; turning it off is audited at
  medium. `GET /api/v1/scans/sensor-opt-in-impact` (`scans:read`) returns the
  switches and the scans that ask for either (at most 100), for the banner
  shown to existing organizations. Enabling a switch never overrides a
  sensor's local policy: the job still goes only to sensors whose own policy
  accepts it.
- **Install dialog.** `GET /sensors/{id}/config-templates` returns `policy`, a
  sensor-policy/v1 template (`configs/sensor-templates/policy.tmpl`)
  prefilled with the ranges of the sensor's scan zones (none for a sensor in
  the default zone, which scans public targets), tools from the sensor, and
  custom templates and interactsh off. The docker, Compose and Kubernetes
  snippets mount it read-only and require it (`SENSOR_LOCAL_POLICY`), set
  `SENSOR_ALLOW_PRIVATE_TARGETS=1` when a zone range is private, and run the
  sensor hardened (read-only root filesystem, all capabilities dropped, no
  privilege escalation, seccomp RuntimeDefault, writable tmpfs/emptyDir
  scratch directories). The Helm snippet turns on `sensor.localPolicy` of
  chart 0.11.0.

## Network egress and proxies (RFC-034, proposed)

> Design: [RFC-034](../rfcs/RFC-034-sensor-network-egress.md). Status:
> **Proposed**; Phase 0 shipped on the sensor side. sdk-go v0.15.0 and later
> (sdk-go#111, sensor#102) add `SENSOR_CONTROL_PROXY`, `SENSOR_CONTENT_PROXY`
> (content sources, including `SafeHTTPClient`, which checks the target before
> the proxy) and `SENSOR_SCAN_PROXY` (`inherit` or `direct`). "Today" below
> describes sensors built on older SDKs; "Proposed" (profiles, forwarder) is
> not built.

A sensor sends three kinds of traffic, and RFC-034 configures each one
separately:

| Class | Today | Proposed |
|---|---|---|
| **Control**: sensor → platform | `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` on the sensor host (`httpsec.NewAPIClient`, `http.ProxyFromEnvironment`). `SENSOR_CA_CERT_FILE` trusts an inspecting proxy's or a private CA. | Unchanged, sensor-local only. `SENSOR_CONTROL_PROXY` (a URL or `direct`) overrides the environment for this channel alone. |
| **Content**: templates, DBs, rules, KEV/EPSS | Upstream sources use `httpsec.SafeHTTPClient`, which has **no proxy**: they fail on proxy-only networks. Mirrors and trivy's DB download use the environment. | Sensor-local. `SENSOR_CONTENT_PROXY`, else the control proxy. `SafeHTTPClient` checks the request URL before it hands the request to the proxy. |
| **Scan**: scanner → target | Scanner processes inherit the proxy variables (`core/scanner_env.go`), so internal targets can be sent to the corporate egress proxy unless `NO_PROXY` lists them. Tools that ignore the variables go direct. Nothing records the path. | Per scan zone (and optionally per tool), configured on the platform as an **egress profile**. Without a profile a zone keeps `inherit`, which is today's behaviour. |

**Today's advice.** If a sensor reaches the platform through a corporate
proxy and also scans internal ranges, list those ranges and domains in
`NO_PROXY`. Go matches a CIDR entry only when the target is an IP literal, so
also list domains (`.corp.example`). Each tool parses `NO_PROXY` its own way,
and Go reads the environment once per process. A segment
that the sensor can reach only through a proxy should get its own sensor
inside it. Use one zone per segment (scan-zones.md).

**Proposed model, in brief.**

- **Profiles.** An `egress_profile` is an ordered list of proxy endpoints:
  `http`, `https`, `socks5` or `socks5h`, with host and port.
  - Its auth is `none`, `local` (credentials stay on the sensor host,
    `SENSOR_EGRESS_CREDENTIALS_DIR/<ref>`) or, later, `basic` stored on the
    platform and HPKE-sealed per command to key-bound sensors (RFC-032 D5).
  - It also holds an optional CA for an `https://` proxy endpoint, DNS
    (`proxy` or `local`), a health target inside the segment, and a
    revision.
  - Zones reference one profile (`scan_zones.egress_profile_id`), with
    per-tool overrides (`profile`, `direct`, `refuse`).
- **Delivery.** Profiles of the sensor's zones go out with the RFC-033 policy
  echo, without credentials, and are re-read when `config_version` changes.
  A command carries only `egress: {profile_id, revision, mode}`, never a
  proxy URL.
- **Host veto.** `SENSOR_SCAN_EGRESS=platform|direct-only|local` is declared
  in the manifest. Dispatch respects it, and a command that arrives anyway
  fails as `egress-refused-by-host`.
- **Forwarder.** Each proxied job runs its tools through an SDK forwarder on
  `127.0.0.1` (HTTP CONNECT and SOCKS5, random per-job credentials).
  - It checks every destination against job targets ∩ zone ranges ∩ the
    operator's local allow-list, plus the hard deny list.
  - It adds the proxy credentials and fails over in the administrator's
    order.
  - Tools: nuclei, httpx, katana and naabu (TCP connect only, no ping
    discovery) use `-proxy`. trivy image uses `HTTPS_PROXY` in its own child
    environment. Local scanners (semgrep, betterleaks, trivy fs) have no
    scan egress.
  - A tool that cannot use the profile fails the command with
    `egress-unsupported`. It never goes direct.
- **Health.**
  - The sensor checks each endpoint: TCP, TLS, the proxy handshake, then the
    health target. A failure in the last step only means the segment is
    unreachable; the proxy is up.
  - Circuit breakers open after 3 proxy failures, from 30 s up to 10 min with
    jitter. One connection makes at most N attempts for N endpoints.
  - The heartbeat carries an `egress` member. Activity events are
    `egress_degraded`, `egress_down`, `egress_recovered` and
    `egress_auth_failed`. The health flag is `egress_down`.
  - Dispatch skips sensors whose profile is down. A zone with no reachable
    path fails its run once, with `ZONE_UNREACHABLE`.
- **Throttling is not failover.** A 429, a block, or a proxy saying the
  target is unreachable never switches proxy. The sensor backs off, honours
  `Retry-After`, and reports `target_throttled` / `target_blocked`. Rotating
  proxies to evade a target's limits is an explicit non-goal.
- **Visibility and audit.**
  - The path taken is recorded per job in `tool.properties.egress`, shown on
    the run page and in the preview.
  - Every profile and zone-path change is audited: `egress_profile.*`,
    `scan_zone.egress_changed`, `scan_zone.tool_egress_changed`. Credentials
    are never shown in the audit.
  - Permissions: `sensors:egress:read|write|delete`, admin and owner only.

## Tool settings (RFC-038, proposed)

> Design: [RFC-038](../rfcs/RFC-038-sensor-tool-settings.md). Status:
> **proposed; per-scan settings for naabu and nuclei shipped** (below).

**Per-scan settings (shipped).** A scan command's settings travel in the
payload key `config` (`pipeline.PayloadKeyConfig`), the key the SDK reads
(`ScanCommandPayload.Config`). Pipeline steps used to send them as
`step_config`, which no sensor reads, so every step ran with its tool's
defaults. On the sensor, the SDK's executor resolves the keys the tool's
settings schema declares (scope `scan`) into `core.ScanOptions.Settings`
and fails the command on any value the schema refuses; other keys are
reported in the command result's `ignored_config_keys`. The sensor declares:

| Tool | Keys | Notes |
|---|---|---|
| naabu | `ports`, `top_ports`, `exclude_ports`, `rate`, `retries` | port lists only (`80,443,8000-8100`, `top-100`, `top-1000`, `full`); `rate` only lowers the sensor's rate |
| nuclei | `tags`, `exclude_tags`, `severity` | `dos`, `fuzz`, `fuzzing`, `intrusive` refused as tags; `exclude_tags` adds to the sensor's |

The api checks the same rules when a step is saved
(`SecurityValidator.ValidateStepConfig` -> `pipeline.NormalizeStepConfig`,
error code `INVALID_STEP_SETTING`) and normalizes values at dispatch
(comma-separated lists to arrays, numeric strings to numbers, tags
lowercased). `allow_interactsh` is refused on a pipeline step. The sensor
stays the authority: `pipeline.NormalizeStepConfig` mirrors its schemas until
the platform stores the schemas sensors report (RFC-038 P2).

Otherwise a tool's options are not managed by the platform: the sensor's
wrappers take them from host env vars or code. The design: each tool declares a typed settings schema,
registered by digest in the manifest; admins edit a generated form on the
sensor's page; the api validates and audits, then pushes a signed,
versioned settings document that the sensor re-validates, stores and
applies from the next job, reporting the applied version.

The SDK also reads `rate_limit`, `concurrency` and `bulk_size` from a
command's `config` (whole numbers; anything else fails the command); the
sensor caps them at its `SENSOR_NUCLEI_MAX_*` ceilings.

## Custom template trust (RFC-038 §6.12)

> Design and threat model: [RFC-038 §6.12](../rfcs/RFC-038-sensor-tool-settings.md).

| Step | Where | What |
|---|---|---|
| Upload | `internal/app/template/validator.go` (`NucleiValidator`) | refuses `code`, `javascript`, `headless`, `file` and self-contained templates on the parsed document |
| Delivery | `command.Service.Poll` → `template.PayloadSigner` | re-validates the command's templates and adds `custom_templates_envelope`: a DSSE envelope over a manifest bound to tenant, polling sensor, command and a 1 h expiry, listing every template's SHA-256; the stored command is unchanged |
| Keys | `scannertemplate.Keyring`, `initTemplateKeyring` | per-tenant Ed25519 via HKDF from `APP_TEMPLATE_SIGNING_KEY` (or derived from `APP_ENCRYPTION_KEY`); `GET /api/v1/scanner-templates/signing-key` shows the public key |
| Sensor | sdk-go `core.TemplateVerifier`; sensor `nuclei.CheckCustomTemplates` | verifies before parsing against `SENSOR_TEMPLATE_SIGNING_KEYS`, fails closed; custom templates run in their own nuclei run with `-exclude-type code,file,headless,javascript`, the sensor's own templates with `-disable-unsigned-templates` |

## Control plane under load (RFC-035)

A sensor's scanners can saturate its CPU, memory and disk, and the sensor
still has to heartbeat. [RFC-035](../rfcs/RFC-035-sensor-control-plane-under-load.md)
measured where this breaks and splits the fix into sensor-side (SDK) and
platform-side work.

**What the platform does** (owner decisions D1–D3):

- **Per-sensor deadline and ladder (D1).** Each heartbeat stores the interval
  the sensor follows and its deadline; the health controller walks a silent
  sensor online -> late -> stale -> offline against that deadline (see
  "Fleet health"). This replaced the hard-coded 90 s, so a sensor told to
  back off is no longer convicted for following the advice (B1), and `late`
  and `stale` are stored states that last as long as the ladder says (B2).
  The worker's backstop sweep (`jobs.SensorHealthChecker`,
  `WORKER_HEARTBEAT_TIMEOUT`) uses the same ladder and only touches sensors
  still stored `online`.
- **Advice inside the deadline (D2).** The doorbell never advises more than
  half of the offline distance (45 s with the 90 s floor); with the stored
  interval the deadline follows the advice anyway.
- **Notified only at offline, never while the platform is slow (D3).**
  `sensor.offline`, the `sensor.disconnected` audit event and the activity
  entry fire only at the offline step. Each tick the controller asks a
  platform-health guard (`internal/app/sensor/platform_health.go`) first; it
  holds every offline conviction (the sensor stays or goes `stale`, nobody
  is notified, a WARN log says why) while:
  - the API started less than `SENSOR_HEALTH_STARTUP_GRACE` ago (default:
    the offline distance of a sensor on the SDK's 60 s default, 4 min);
  - the controller's previous tick ran more than two intervals ago (the
    process was stalled);
  - the p95 of the heartbeat handler's latency (the write and the doorbell
    query, v1 and v2) over the last 2 min is at or above
    `SENSOR_HEALTH_SLOW_HEARTBEAT` (default 2 s, at least 5 heartbeats).
- **`control` stored and shown.** The heartbeat's `control` member is read
  leniently, clamped (`pkg/domain/sensor/control.go`) and stored
  (`sensors.reported_control`, `control_reported_at`); `GET /sensors/{id}`
  returns it and the console's sensor drawer shows a "Control channel" card.
- **Leases (D6).** Running commands of a sensor that died go back to the
  queue when their lease runs out ("Command leases" above).
- **Heartbeat gap metric.** Every heartbeat that had a previous one feeds
  two Prometheus histograms with no labels (fixed cardinality whatever the
  fleet size):
  - `sensor_heartbeat_gap_seconds`: the time between two heartbeats;
  - `sensor_heartbeat_gap_ratio`: that time divided by the interval the
    sensor followed (1 = on time).
  The gap comes from the stored deadline (`heartbeat_due_at` minus the
  interval), so polls and other requests do not shorten it.
- **Recovery entry.** A heartbeat that arrives after its own deadline had
  made the sensor late, stale or offline adds one `heartbeat_recovered`
  activity entry ("Heartbeats back after a 1m20s gap (was late)"; details
  `was`, `gap_seconds`, `interval_seconds`).
  - It is judged on the heartbeat deadline, not on whether the controller
    already ticked.
  - Status entries coalesce on type, so a sensor that keeps slipping folds
    into one row with a repeat count.
  - A sensor back from `offline` gets the usual `online` entry instead.
- **Heartbeat history and sparkline.**
  - **Storage.** Each tenant sensor's heartbeats are aggregated on write
    into 15-minute buckets (`sensor_heartbeat_history`, migration 000263;
    one upsert per heartbeat). A bucket holds: heartbeats, average and
    largest gap, the interval followed, the largest timer lag, and the
    heartbeats the sensor reported lost.
  - **Retention.** A controller deletes buckets older than 48 h every hour,
    so there are at most 192 rows per sensor.
  - **Read.** `GET /api/v1/sensors/{id}/heartbeat-history?hours=24`
    (sensors:read, at most 24 h) returns the buckets that had a heartbeat,
    oldest first.
  - **Display.** The Control channel card draws them as a 24 h bar
    sparkline: the bar height is the largest gap, a warning bar is a slot
    where the sensor was late, an empty slot had no heartbeat, and a dashed
    line shows the interval. Sensors that send no `control` block still get
    the card for the sparkline.

**What the SDK does** (sdk-go, RFC-035 Phase 1):

| | |
|---|---|
| Heartbeat client | Its own `http.Client`: a clone of the API client's transport (proxy, TLS, dial guard) with its own connection pool. `Config.ControlTimeout`, default 15 s. |
| Failure | At most 1 retry (an idle connection the platform closed). After a failed heartbeat, the next one follows in about 10 s (`core.HeartbeatRetryDelay`, jittered), never later than the interval. A rejected key backs off through the auth gate as before. |
| Report building | Tool version probes run in the background after the first one (`ToolRegistry.SetBackgroundRefresh`). The manifest exchange is bounded by 15 s. |
| `control` member | `{"interval_s","gap_s","lag_ms","build_ms","rtt_ms","failures"}`, stored by the API (above). `lag_ms` is how late the heartbeat timer fired (the sensor waiting for a CPU); `build_ms` is report building. |
| Scanner processes | Linux: process group at nice +10, best-effort I/O level 7, `oom_score_adj` 500, set right after start. `SENSOR_SCANNER_PRIORITY=normal` turns it off. |
| Slots | Leave memory free for the sensor: a tenth of its memory, 256 MiB to 1 GiB (`resource.DefaultReservedMem`). |

The SDK echoes the lease epoch of each command it holds on `complete` and
`fail` (`X-OpenCTEM-Lease-Epoch`, sdk-go v0.16.0); the API accepts both
forms, so older sensors keep working (fenced by sensor and state only).

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
