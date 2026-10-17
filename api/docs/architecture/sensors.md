# Sensors: vocabulary, code layout and protocol v2

> RFC: [RFC-023](../rfcs/RFC-023-scan-zones-and-scanners.md) §4 (D18) and §9.5.
> Contract of the rename: [RFC-023-sensor-rename-contract.md](../rfcs/RFC-023-sensor-rename-contract.md).
> Protocol v2: [RFC-026](../rfcs/RFC-026-sensor-results-ingest.md) (results) and
> [RFC-029](../rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md) (everything else; protocol v1 retired 2026-10-05).
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
| Application | `internal/app/sensor` (service, selector, config templates) |
| Persistence | `internal/infra/postgres/sensor_repository.go`, `sensor_apikey_repository.go` |
| HTTP | `internal/infra/http/handler/sensor_handler.go` (management), `ingest_handler.go` (sensor key authentication, services shared with the v2 control plane) |
| Health | `internal/infra/controller/sensor_health.go`, `internal/infra/jobs/sensor_health_checker.go`, `internal/infra/redis/sensor_state.go` |
| Protocol v2 control plane | `pkg/sensorproto/v2/control.go` (wire), `internal/infra/http/handler/sensor_control_v2_handler.go`, `internal/app/command/transition.go` (idempotent transitions), mounted by `routes/sensor_v2.go` |
| Protocol v2 results | `pkg/sensorproto/v2` (wire), `internal/infra/http/middleware/ingest_v2.go` (edge), `internal/infra/http/handler/sensor_results_v2_handler.go`, `internal/infra/http/routes/sensor_v2.go`, `internal/app/ingest/v2*.go`, `strictjson.go`, `pkg/domain/ingestreport` |

## Protocol v1 (retired)

Protocol v1 (`/api/v1/agent/*`, `agent_id` in bodies, `agent_preference` in job
payloads) was retired on 2026-10-05, ahead of its announced 2027-04-01 sunset:
the live fleet had sent no v1 request for a day, and every sensor from v0.9.0
on speaks v2 for the whole surface. The `pkg/sensorproto/legacyv1` package,
the `/api/v1/agents` → `/api/v1/sensors` redirect, the v1 golden test and the
pinned-SDK compatibility job went with it. A sensor older than v0.9.0 gets 404
on every call and has to be upgraded. The v1-only routes without a v2
successor (`ingest/sarif`, `ingest/recon`, `ingest/scan`, `ingest/scanners`,
`scans`, `telemetry-events`, `credentials/ingest`) are gone too.

`tools/lint/sensorvocab` still fails on any Go identifier, import path or file
path that says *agent* outside the rename tooling and the AI-agent
identifiers.

## Suppression rules for the sensor-side gate

`GET /api/v2/sensor/suppressions` (RFC-023 §9.2b) returns
the sensor's tenant's approved, unexpired suppression rules that are tied to
no asset or to an asset the sensor reaches (see
[Lookup reach](#lookup-reach-fingerprints-baseline-diff-suppressions)) as
`{"count": n, "rules": [{rule_id, tool_name, path_pattern, asset_id, expires_at}]}`.
The sensor's security gate (`-fail-on`) uses them to stop failing a CI job on a
finding the platform has suppressed. Tenant from the sensor identity; platform
sensors get 403; an empty list when the suppressions module is disabled.
Ingest applies the same rules server-side whatever the sensor does. Before this
route the SDK called the user route `/api/v1/suppressions/active` with its
sensor key and always got 401.

## Lookup reach (fingerprints, baseline diff, suppressions)

A sensor's lookups answer only about the assets it may reach, so a sensor in
one scan zone does not learn which findings, repositories or suppressed paths
exist in another (research/84 F-BOLA-2, F-BOLA-3). Code:
`internal/app/ingest/sensor_reach.go`, `internal/infra/postgres/sensor_reach_repository.go`.

**Reach.** A sensor reaches the assets covered (the result-binding coverage:
the same host or a subdomain of a domain target, the repository path or below
it, an address in a range; an asset's IP addresses count) by

- the targets of the commands assigned to it that are open (pending,
  acknowledged, running) or ended in the last 24 hours (a retry queue re-checks
  fingerprints of a report it could not send at once), at most the newest 1,000;
- the address ranges of the scan zones it serves (`scan_zone_sensors`). The
  default zone has no ranges and adds nothing.

A collector (sensor type `collector`) and a sensor whose grant profile is
`collector` (or `collector:<name>`) or `ci-runner` push results nobody asked
for, anywhere in the tenant: their lookups stay tenant-wide. Every other
sensor, `legacy-broad` included, is limited to its reach; a sensor with no
zone and no command reaches nothing.

**Answers outside the reach** are the answers for something that does not
exist, so the lookups are no existence oracle, and each is safe for the
caller:

| Lookup | Outside the reach |
|---|---|
| `POST /fingerprints/check` | the fingerprint is `missing` (the caller re-sends; ingest deduplicates) |
| `POST /fingerprints/baseline-diff` | a `repository` the sensor does not reach answers as an unknown repository: every fingerprint new, `base_branch_scanned: false` |
| `GET /suppressions` | a rule on an asset the sensor does not reach is left out (ingest still applies it server-side) |

A CI pipeline that needs baseline diffs for any repository uses a CI run token
(`POST /api/v1/ci/runs/{id}/baseline-diff`, RFC-051) or a `ci-runner` sensor.
The lookups are batched: one query for the commands and one for the zone
ranges, one for the assets of the known fingerprints and one for those
assets' names and addresses.

## Heartbeat doorbell

`POST /api/v2/sensor/heartbeat` is also a doorbell (RFC-023 §9.2a): it tells
the sensor *that* something is waiting for it and when to ring again. It never
carries a job, a command text or any other payload. Jobs are still fetched and
claimed with `GET /api/v2/sensor/commands` and
`POST /api/v2/sensor/commands/{command_id}/claim`, so authorization, the zone
claim predicate and claim semantics stay in one place.

### Response fields (additive, all `omitempty`)

| Field | Type | Meaning |
|---|---|---|
| `pending_jobs` | int | Commands this sensor could claim right now, capped at 100. Exactly what the poll would offer: pinned to the sensor or unpinned, pending, not expired, not scheduled for later, zone claim predicate (`zoneClaimPredicate`, incl. the tool match), capability gate. `> 0` ⇒ poll now. Not computed for platform sensors (no tenant poll). |
| `next_heartbeat_seconds` | int | Advised interval. 5 s while work is waiting or while a command the sensor claimed was canceled within the last lease period (so it hears `cancel_command_ids` within seconds), 30 s idle, the maximum interval when the doorbell query itself took ≥ 250 ms (platform under load). Clamped to `[SENSOR_HEARTBEAT_MIN_INTERVAL, SENSOR_HEARTBEAT_MAX_INTERVAL]` and never more than the derived maximum `min(offline distance / 2, SENSOR_COMMAND_LEASE / 3)` (45 s with the defaults: half the ladder's 90 s floor, or of `WORKER_HEARTBEAT_TIMEOUT` when shorter, RFC-035 D2; and a third of the lease, so a sensor holding a command renews its lease at least twice before it runs out, RFC-074). The heartbeat stores the advice as the sensor's deadline ("Fleet health"), so a sensor that follows it is never marked offline. |
| `actions` | []string | Typed directives from a closed set: `pause`, `resume`, `drain`, `rotate_key`, `update`. Rung today: `pause` (sensor disabled by an admin), `rotate_key` (the presented key expires within `SENSOR_KEY_RENEW_BEFORE`, default half of `SENSOR_KEY_TTL`). `resume`, `drain`, `update` are reserved. There is no free-form or shell verb (RFC-023 §10.4 R-4); a sensor ignores a value it does not know. |
| `config_version` | string | 16 hex chars, opaque. A digest of what the platform governs about the sensor: capabilities, tools, max concurrent jobs, execution mode, operator config, the presented key's expiry and the assigned scan zones with each zone's last change. Heartbeat metrics and `last_seen_at` are not part of it (both rewrite `sensors.updated_at` on every heartbeat, which is why `updated_at` cannot be the source). |

### Who gets what

A sensor announces it acts on the doorbell with the request header
`X-OpenCTEM-Sensor-Features: doorbell` (comma-separated list,
case-insensitive).

On protocol v2 the doorbell is always on (see
[Protocol v2 control plane](#protocol-v2-control-plane)):

| | heartbeat response |
|---|---|
| idle | `config_version`, `next_heartbeat_seconds: 30` |
| work waiting | + `pending_jobs`, `next_heartbeat_seconds: 5` |
| key in renewal window | + `actions: ["rotate_key"]` |
| disabled | **200** `status: paused`, `actions: ["pause"]`, no other hint, no DB write |
| revoked / expired key | 401 |

A disabled sensor may reach the heartbeat (and `GET /hello`) only, to be told
to pause; every other route still refuses a disabled key.

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
`SENSOR_HEARTBEAT_MIN_INTERVAL` (5s), `SENSOR_HEARTBEAT_MAX_INTERVAL` (5m, can
only lower the derived maximum below), `SENSOR_HEARTBEAT_SLOW_QUERY` (250ms; a
slower doorbell query advises the maximum interval),
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

1. `pending_jobs > 0` ⇒ poll `GET /api/v2/sensor/commands` immediately, then
   claim as today. No hint ⇒ keep the fixed poll interval (older servers).
2. Use `next_heartbeat_seconds` as the next heartbeat delay when present;
   fall back to the configured interval when absent.
3. With hints present, drop the separate fixed 30 s poll: poll on the doorbell
   only (plus once at start-up).
4. `pause` ⇒ stop polling and starting jobs, keep heartbeating; resume on the
   first heartbeat without `pause`. `rotate_key` ⇒ `POST /api/v2/sensor/keys`.
   Ignore unknown actions.
5. A changed `config_version` means the platform changed something about this
   sensor; the sensor re-reads what it needs on the next poll.

Code: `internal/app/sensor/doorbell.go` (hints, intervals, config version),
`internal/infra/postgres/command_repository.go` (`PendingWorkForSensor`),
`internal/infra/http/handler/ingest_handler.go` (`AuthenticateSource`,
`Heartbeat`), `pkg/domain/sensor/doorbell.go` (the `Action` enum),
`internal/infra/http/handler/sensor_control_v2_handler.go` (the v2 wire).

## Outbox state on the heartbeat

A sensor built on an SDK with a durable outbox (results written to disk first,
delivered when the platform accepts them) reports the state of that queue on
the heartbeat request, as an optional `outbox` object:

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
change.

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
cloned identities"), `version_unsupported`, `sdk_advisory` (see "Build information"),
`no_tools` (a scanning daemon with no tools), `error_reported`,
`heartbeat_late` (the sensor is late or stale, or its last delivered heartbeat
came more than 1.5 intervals after the previous one, `control.gap_s`) and
`control_slow` (`control.lag_ms` or `build_ms` above 5 s), and from the
config report (below) `config_check_failed`, `config_check_warning` and
`config_report_stale`. An online sensor with any reason is `degraded`.

**Sensor products and release lines** (RFC-037 §11): the platform knows
several sensor products, listed in `versions.yaml` and built into the API
(`internal/versions`): the scanning sensor (`openctemio-sensor`) and the
Tenable.sc connector (`openctemio-connector-tenable`), each with its own
`latest` and `min`. A sensor's product is what it reports (heartbeat
`sensor.name`, else its User-Agent product token); one that reports none is
the scanning sensor. `product` in the sensor response is that product,
`product_known` whether the catalog lists it, and `product_latest_version` /
`product_min_version` its release line. `version` is normalized to one form
(`0.4.2`, `v0.4.2` and `vv0.4.2` all read `v0.4.2`); `version_status` compares
it with the product's own line: `latest`, `update_available`, `unsupported`
(below the product's minimum: health reason `version_unsupported`) or
`unknown` (no version, a dev build, or a product the catalog does not list: a
custom sensor gets no version verdict; its compatibility is the protocol and
the capabilities it advertises). A git-describe build (`v0.4.2-3-gabc1234`)
counts as its tag. The stats response lists the catalog (`products`: `id`,
`latest_version`, `min_version`, `image`). A release bump changes
`versions.yaml` only; there is no setting for it (`SENSOR_LATEST_VERSION` and
`SENSOR_MIN_VERSION` are refused at startup).

**Other fields**: `key_expires_at`, `last_offline_at`, `last_error_at`,
`started_at` and `uptime_seconds` (from the heartbeat's `uptime_seconds`, stored
as `sensors.process_started_at`, migration 000249), `scope`.
`ip_address` is the heartbeat's client address under the trusted-proxy rule
(`SERVER_TRUSTED_PROXIES`): behind the built-in gateway it is the address the
gateway saw (`X-Real-IP`), so a sensor running in a container on the platform
host shows the container network's gateway address, which is where it really
connects from.

**Stats** count the same rows the list returns: the tenant's own sensors.
Shared sensors (`scope = 'instance'`) are in neither. Their queue
(`get_next_platform_job`) is shared fairly across tenants: within a priority
class, the tenant with the fewest platform jobs in flight goes first
(migration 000461, RFC-030 §5.7). The stats also add `by_state` (every state, zeros included), `by_version_status`,
`needs_attention`, `can_take_jobs`, `jobs_running` and `job_slots`.

## Shared sensors on the tenant plane

Platform sensors become **shared sensors** (instance scope) in every edition;
the design, access layers, deployment defaults and rollout are in
[RFC-100](../rfcs/RFC-100-shared-sensors.md). Until its gate (§11) is met,
no organization may use them.

A sensor has a **scope** (`sensors.scope`, [RFC-100](../rfcs/RFC-100-shared-sensors.md) §3.1):

| `scope` | `tenant_id` | Meaning |
|---|---|---|
| `organization` | the organization | an organization sensor (pairing, RFC-052) |
| `instance` | `NULL` | a shared sensor: it belongs to the instance and serves the organizations the access policy allows |

The table enforces it (`chk_sensors_scope_tenant`: `(scope = 'instance') =
(tenant_id IS NULL)`), and the scope is fixed at creation
(`trigger_sensors_scope_immutable`): an organization sensor never becomes a
shared one, so no organization's keys, grant or history move to the instance.
Rows that refer to a sensor through `(tenant_id, sensor_id)`:

- `sensor_grants` and `sensor_keys` may belong to a shared sensor. Their
  `tenant_id` is `NULL` then, and only then (trigger
  `sensor_child_tenant_matches_scope`); a plain foreign key on `sensor_id`
  keeps the cascade on delete.
- `scan_zone_sensors`, `sensor_tool_settings` and `collector_assets` keep
  `tenant_id NOT NULL`, so the composite foreign key refuses a shared sensor:
  it is never a zone member, has no organization's tool settings and collects
  no assets.
- `ingest_reports` holds a shared sensor's report of a shared job in the
  command's organization: a plain foreign key on `sensor_id` and the trigger
  `trigger_ingest_reports_sensor_binding` keep an organization sensor's
  reports in its organization and store a shared sensor's report only with a
  shared job of that organization it holds; a shared sensor pushes nothing
  ([result binding](sensor-result-binding.md#shared-sensors)).

A shared sensor has no "home" organization. Managing shared sensors belongs to
the platform admin console (RFC-022); on the tenant plane they do not exist:

- **Access.** One rule decides whether an organization may send scans to
  shared sensors (`scanpolicy.Service.SharedSensorsAllowed`; the scan
  trigger, the pipeline and the platform scanning view all call it). Every
  layer must allow, and any unreadable layer refuses:
  1. the instance switch, `platform_settings['shared_sensors'].enabled`
     (default off);
  2. the instance administrator's decision for the organization,
     `tenants.shared_sensors_access` (`allow`, `deny`), or, without one,
     `platform_settings['shared_sensors'].new_orgs`: unset by default, and
     unset refuses. Turning the switch on requires `new_orgs` true or false in
     the same request (400 `NEW_ORGS_CHOICE_REQUIRED`). A deny always wins;
  3. the owner's opt-out, the organization setting `shared_sensors.opt_out`.

  Console > System > Platform scanning (`/api/v1/admin/settings/shared-sensors`)
  and `/api/v1/admin/tenants/{id}/shared-sensors`: any administrator reads,
  and a super admin changes either with a reason and a fresh authenticator
  code (critical admin audit row, other administrators emailed). The owner's
  choice is at `/api/v1/organization/settings/shared-sensors`: the owner or
  an administrator reads it, only the owner changes it, and the change gets a
  tenant audit row. The refusal reason names the layer that refused.
  Above the three layers sits the rollout gate (`sharedSensorsReady` in
  `internal/app/scanpolicy/shared_sensors.go`, RFC-100 §11). While it is
  closed, every organization is refused with "shared sensors are not
  available yet", and the console refuses to turn the switch on (409
  `SHARED_SENSORS_NOT_READY`) before it spends the code.
- **Lookups.** `GetByTenantAndID`, the list filter, the dispatch finders
  (`FindAvailable*`, `HasSensorFor*`), tool and capability availability, grant
  summaries and manifests all add `scope = 'organization'` (besides
  `tenant_id = $1`, which a `NULL` never matches).
- **Authentication.** A shared sensor's key authenticates it as a sensor but
  never into an organization: the v2 authenticator sets no tenant context,
  and every tenant-bound sensor route answers 403 `scope-denied`
  (`sensorForV2`, the results receiver). A signed request resolves the key's
  sensor within the key's tenant, which a shared sensor's key does not have,
  so it is refused (`shared_sensor_auth_db_test.go`).
- **One guard for every route on one sensor.** Every `/api/v1/sensors/{id}...`
  route ends with `SensorHandler.OwnSensor`: a sensor that is not one of the
  organization's own (another organization's, or a shared sensor) answers
  404 before the handler runs, reads and writes alike, today's routes and any
  added later. `platform_sensor_tenant_plane_db_test.go` walks the router and
  checks each one.
- **Shared sensors view.** `GET /api/v1/platform/scanning` (sensors:read or
  scans:read; the "Shared sensors" card on the Sensors page) shows the
  service, not the sensors: whether the organization may use it (`offered`,
  the scan trigger's own shared sensor access rule; false says nothing else,
  not even the egress addresses), each region's state (`available`, `busy`,
  `unavailable`), the tools online shared sensors run, the organization's own
  queued and running shared jobs, the queue limit, and the **egress
  addresses** to allowlist (`egress`: the list for every region first, then
  one per region). No sensor id, name, host, address, version, node count,
  capacity or other organization's load. The card links administrators to
  the owner's opt-out.
- **Egress addresses.** Console > System > Platform scanning, "Egress
  addresses" (`GET/PUT /api/v1/admin/settings/shared-sensors/egress`,
  `platform_settings['shared_sensors_egress']`): IP addresses or CIDR ranges
  for every region and per region label (sensor region tokens, at most 32
  regions and 64 entries per list). Only public addresses: any entry that is,
  or overlaps, an internal range of ctis `addrscope` (private, loopback,
  link-local, metadata, CGNAT, multicast, IPv6 forms that carry such an IPv4
  address) is refused with 400, so the list never discloses the operator's
  internal network. Any administrator reads; a super admin replaces the list
  with a reason and a route-level step-up (critical admin audit row
  `platform.shared_sensors_egress_changed`, other administrators emailed).
  The list is normalized (host bits cleared, duplicates removed, sorted).
- **Platform jobs.** A command, run task or run stage of a platform job never
  carries a sensor id or name (`platform: true` instead). Text the platform
  sensor wrote (command logs, error message, result, run task error) is read
  through `sensordom.RedactPlatformText`: private, loopback, link-local and
  shared (100.64/10) addresses and absolute host paths become `[platform]`.
  Platform sensors scan public targets only, so a public address or a host
  name in their output is the tenant's own target and is kept.
- **Evidence.** A platform sensor's sighting is recorded with the source
  `sensor:platform` and no `observed.sensor_id`; the review queue labels it
  "platform sensor".
- **Events.** The health controller writes no tenant audit row or
  notification for a platform sensor going offline.
- **Claims.** A job queued for platform sensors (`is_platform_job`) is never
  offered to, counted for or claimable by an organization's own sensor: the
  poll, the doorbell, the batch claim and the claim by id share
  `tenantJobPredicate` (`command_repository.go`).
- **Grant.** A platform sensor's grant is least privilege whatever writes it:
  no credentials, no push ingest, tier 1 at most, public targets, no remote
  update, never `legacy-broad`, job types scan, validate and retest only (no
  limit becomes exactly these). The insert trigger `sensor_grants_default`
  gives it `easm-external`; the trigger `clamp_shared_sensor_grant` on
  `sensor_grants` clamps any later edit (migrations
  `shared_sensor_grant_least_privilege` and `sensor_scope`).
- **Workflow steps.** Every workflow step about to be queued for platform
  sensors goes through the scan trigger's own target check
  (`scan.Service.PlatformTargetRefusal`: no asset group, no internal target,
  proof where the operator requires it, no bug-bounty program target), on the
  step's own targets. A run started from a workflow directly has no trigger
  decision, and a later step may carry targets found after the trigger
  checked the seeds. A refusal or a failed lookup keeps the step on the
  organization's own sensors.
- **Deployment defaults.** `MANAGED_SERVICE` (environment, default false,
  read at start-up) marks a hosted multi-tenant service and changes defaults
  only, never a feature or a stored value (RFC-100 §6):

  | Setting (`platform_settings` key) | Self-hosted default | `MANAGED_SERVICE=true` default |
  |---|---|---|
  | Verified domain before platform sensors scan (`platform_sensor_proof`) | off | on |
  | Shared sensors may scan internal zones (`shared_sensor_internal_zones`) | off | off |

  The internal-zones setting is stored but **not enforced yet**: nothing
  reads it until instance scan zones and their signed zone ranges land
  (RFC-100 §6.1). Its GET answers `enforced: false` and the console labels
  the card "Not enforced yet". Whether a self-hosted install defaults it on
  is decided when it is wired.

  Once an administrator saves a value in Console > System > Platform
  scanning, the stored value wins. The GET routes return the value in force,
  `default` (the deployment default) and `version` (0 while nothing is
  stored). An unreadable stored value fails closed: proof required,
  internal zones refused. Turning internal zones on assigns no zone: the
  administrator still assigns each instance scan zone to organizations.
  Changes: super admin, reason, fresh authenticator code (route step-up),
  critical admin audit row, the other administrators emailed
  (`/api/v1/admin/settings/platform-sensor-proof`,
  `/api/v1/admin/settings/shared-sensor-internal-zones`).
- **Anomaly signals.** Three per-organization daily counts
  (`scanpolicy.Service.Observe*`, counters in Redis, keys carry the
  organization and the UTC day and expire after 48 hours):
  distinct registrable domains (eTLD+1, a HyperLogLog estimate, so no target
  is stored) of every job queued for shared sensors (single scans, zone
  batches and workflow steps); failed shared jobs (`command.Service.Fail`);
  targets the platform deny list refused, on any sensor (the scan gate's
  `logRefusedTarget`). When a count first reaches its threshold that day, one
  alert: the metric `shared_sensor_anomalies_total{signal}`, a warning log
  line, an admin audit row `organization.shared_sensor_anomaly` (severity
  high, the organization as resource, the count and threshold, never a
  target) and an email to every administrator. Events are counted in
  `shared_sensor_signal_events_total{signal}`. Metrics are labeled by signal
  only. Thresholds: `platform_settings['shared_sensor_anomaly_thresholds']`
  (defaults 25 domains, 50 failures, 5 deny-list hits per day; 0 turns a
  signal off), `/api/v1/admin/settings/shared-sensor-anomaly`, same gate and
  audit as above. The signals are detective: nothing that admits or refuses a
  scan reads them, so a missing or failing Redis loses the signal (logged)
  and never blocks a scan. The response to an alert is the per-organization
  deny (`/api/v1/admin/tenants/{id}/shared-sensors`).
- **Scanner identity.** What the operator publishes so a target's owner can
  tell where scans come from:
  - User-Agent. Sensor traffic to the platform and to the services its
    collectors call carries `<product>/<version> openctem-sdk-go/<version>`
    (sdk-go `pkg/useragent`). Tools run through the sdk-go tool runtime send
    `openctem-<tool>/<version>` unless the tool's `http.user_agent` setting
    (Tool settings, RFC-038) sets another value. A hosted operator sets that
    setting on shared sensors to a value naming the service and its
    information page, for example
    `openctem-scanner/1.0 (+https://scanner.example.com)`.
  - Reverse DNS. Give every egress address of a shared sensor a PTR record
    under a name the operator controls (for example
    `scanner-1.eu.scanner.example.com`), with a matching forward record.
  - Information page. Serve a page at that name (HTTP and HTTPS) that says
    the address belongs to a security scanning service, who runs it, the
    abuse contact, the published list of scanner addresses per region, and
    how a target owner asks to be excluded (the operator adds the name or
    range to the platform deny list, `SCOPE_DENY_EXTRA`).
  - Egress addresses. Keep the scanner egress addresses separate from the
    API and console addresses, so the reputation of one does not affect the
    other, and publish them to organizations (RFC-100 §9).

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

**SDK**: informational, from `versions.yaml` (`sdk.latest`, `sdk.advisories`).
`sdk_status` per sensor is `advisory` (an SDK release with a published
security advisory: health reason `sdk_advisory`, so a heartbeating sensor is
`degraded`), `outdated` (below the latest, no health effect), `current`, or
`unknown` (no SDK version known). There is no SDK minimum. The sensor
responses carry `sdk_name`, `sdk_version`, `sdk_status`, `sensor_product`,
`sensor_commit`, `sensor_build_time`; the stats add `sdk_latest_version`,
`sdk_advisories`, `by_sdk_version` (`unknown` for none) and `by_sdk_status`; `GET /sensors?sdk_version=v0.9.0` (or `unknown`)
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

## Task logs

A sensor that lists feature `logs` on hello sends what each task's tool
logged, through its outbox, to `POST /api/v2/sensor/commands/{id}/logs`
(RFC-029 §4.4.1). Only the sensor holding the command writes; a batch is
stored once per `(command, seq)`; a command keeps at most 200 batches and
2 MiB, the rest is counted as dropped. The platform caps, cleans and redacts
every line again (`internal/app/commandlog`), stores it in `command_logs`
(migration 001130) and the `command-log-retention` controller deletes it after
14 days. The run page shows a task's lines (Runs, a run, Tasks, Logs) through
`GET /api/v1/scan-runs/{id}/tasks/{task_id}/logs` (`pipelines:read`),
as plain text.

Besides the tool's lines, an SDK with the poller log sink (sdk-go #191) sends
the sensor's own lines, tagged `source: sensor`:

- the command was received;
- the local policy check and each target it skipped, with the reason;
- a refusal before running;
- the outcome: completed, partial, failed, timed out, or kill switch;
- a hand-back to the platform.

A task refused before any tool started therefore has a log. When a task has
no lines but has a refusal or failure reason, the Logs dialog shows "This task
was refused before it ran" (or "failed before it sent any logs") with the
reason, instead of the generic empty state.

## Install snippets

`GET /api/v1/sensors/{id}/config-templates` renders the snippets the Sensors
page shows: `docker` (docker run), `compose` (compose.yaml), `kubernetes`
(Secret + PVC + Deployment; a Job for a one-shot sensor), `helm` (turns on the
sensor bundled with the openctem chart), `yaml` (sensor.yaml), `env`, `cli`.
Templates: `configs/sensor-products/<set>/<format>.tmpl`, one directory per
install snippet set (the `install` key of the product in `versions.yaml`:
`sensor/`, `collector/`, `connector-tenable/`), editable on the API host
(`SENSOR_CONFIG_TEMPLATES_DIR`). The built-in fallbacks in
`internal/app/sensor/config_templates_builtin.go` are generated from the
shipped sets (`go generate ./internal/app/sensor/`, a test keeps them
identical). Templates are product data: the platform passes the same closed
data to every set (API URL, key reference, the product's image and tag from
the catalog, CA, name) and never names a sensor's settings itself.

**A new sensor product needs no platform change** (RFC-094 I2). A product of
your own (for example a sensor built on the SDK) is:

1. a section in the file named by `SENSOR_PRODUCTS_FILE`, in the
   `versions.yaml` product format (`product`, `latest`, `min`, `image`,
   `install`, and `release_identity`, which may be `""`). It may not redefine
   a built-in product or a fixed section, and an invalid file stops the API
   from starting;
2. its snippet set: `<SENSOR_CONFIG_TEMPLATES_DIR>/<install>/docker.tmpl`
   (required) and any other formats.

The Sensors page then lists the product (named by its id), the install
dialog offers its snippets (`?product=<id>`), and its sensors are judged
against its own release line. A sensor reporting a product the catalog does
not list gets version status `unknown`.

Every snippet works as pasted for the release it pins (tests run `bash -n` on
the shell ones and parse the YAML ones; `docker compose config` accepts the
compose file):

- **Product** `?product=<id>`: a catalog product (400 otherwise); default the
  product the sensor reports when the catalog lists it, else the scanning
  sensor. Each product has its own snippet set (`versions.yaml` `install`:
  `sensor` is `<format>.tmpl`, another set is `<set>-<format>.tmpl` and may
  ship only some formats; the others come back empty). A collector always gets
  the collector's set. The response's `product` says which.
- **Image** the product's `image` with its `latest` tag, never `latest`;
  `SENSOR_IMAGE` replaces the scanning sensor's repository (a mirror). The
  response's `image` says which. A product set with a `release_identity` shows
  the `cosign verify` command for that release.
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
- **Data** one named volume / PVC (8Gi in the Kubernetes manifest) at
  `/var/lib/openctem`, holding:
  - `outbox/`: results not yet accepted, so they survive a restart or an
    outage;
  - `state/` (daemon sensors): the paired identity, or the API key the
    sensor renews on its own, so a recreated container comes back with it
    instead of the installed key, which the renewal retired;
  - `content/` (daemon sensors): the scanner content cache (trivy DB, nuclei
    templates, semgrep rules), so a new container does not download it
    again; disposable.

  One volume is one thing to keep and back up (like a credential: it holds
  the sensor's private key; `tar --exclude=./content` leaves out the cache).
  The sensor image declares no `VOLUME` (an anonymous volume would shadow a
  subdirectory of the data volume and looks persistent to the sensor's
  check), and the sensor creates the subdirectories (0700 for state and
  outbox) on a fresh volume. Sensors installed with a volume per
  subdirectory keep working; the sensor README has the migration. The Helm
  snippet sets `sensor.data.persistence.enabled=true` (chart 0.19.0+).
- **Tools**: no snippet lists them. The sensor offers the tools it finds
  (a registered tool whose binary is installed), so the image variant
  defines the set, and the local policy's `tools.allow` narrows it.
  Re-emitting the tools a sensor last reported would pin a reinstalled
  sensor to its old set, so `SENSOR_TOOLS`, `-tools` and `sensor.tools` stay
  out of the snippets. A deployment that sets `SENSOR_TOOLS` keeps working
  (it narrows the detected set). The one-shot examples still name one tool
  (`-tool <name>`), a different mode. The sensor name becomes a slug.

- **Collectors** (sensor type `collector`) get the asset collector's own
  commands (`configs/sensor-products/collector/*.tmpl`): the image
  `SENSOR_COLLECTOR_IMAGE` (default `ghcr.io/openctemio/asset-collector:latest`
  until the collector tags a release), `SENSOR_API_URL`, the API key and
  vendor passwords as files (`SENSOR_API_KEY_FILE`, `LDAP_PASSWORD_FILE`),
  one data volume at `/var/lib/openctem` (state and outbox), a `doctor` check
  before `-daemon`, and no local policy or seccomp profile (a collector takes
  no scan jobs and runs no tool). The Helm tab says the chart bundles the
  scanner only.

### Hardened installs: the sensor's seccomp profile

Every daemon install runs the sensor under its own seccomp profile, so each
tool task can run network-confined (its own network namespace; only its
targets, through its forwarder; RFC-060). The container runtime's default
profile refuses the namespaces this needs.

- **Served by the platform:** `GET /api/v1/sensors/install/seccomp-profile`
  (public, rate limited per IP, `X-Content-SHA256`). It is the sensor
  release's `docker/seccomp/sensor.json`, embedded in the API
  (`internal/app/sensor/seccomp/sensor.json`); a test pins its SHA-256, so a
  change comes from a sensor release on purpose.
- **Checked before use:** the docker and compose snippets download it with
  `curl -fsSL` (with the platform CA when there is one) and run
  `sha256sum -c` against the digest the API rendered into the snippet, before
  the container starts. A tampered or truncated download stops the install.
- **docker:** `--security-opt seccomp=/etc/openctem/sensor-seccomp.json`
  next to `no-new-privileges`. **compose:** `security_opt` gains
  `seccomp=./sensor-seccomp.json`. **Kubernetes:** a `Localhost` profile
  `openctem/sensor-seccomp.json`, put on the nodes by the operator (the
  snippet says how, and how to fall back to `RuntimeDefault`). **Helm:**
  `sensor.sandbox.seccompProfile=openctem` (the chart installs it on the nodes
  with a DaemonSet; the default from chart 0.23.0).
- The default AppArmor profile stays: on hosts that restrict unprivileged
  user namespaces, `apparmor=unconfined` stops confinement working.
- **Setup checklist:** the sensor reports `runtime.sandbox_network`
  (`confined`, or the detected cause: `userns_blocked`, `userns_restricted`,
  `off`, `sandbox_off`, `unavailable`); the catalog explains each code with
  its fix ([fix the setup checklist](../how-to/fix-sensor-setup-checklist.md)).

## Pairing, key-bound identity and grants (RFC-052)

A sensor can join without any key being copied: it pairs with a code and a
fingerprint an administrator compares, and then signs every request with its
own Ed25519 key (RFC 9421). Every sensor has a grant (zones, job types, tools,
tier, targets, credentials, push ingest, remote actions) checked on poll,
claim and results. Code map, events and status:
[sensor-pairing.md](sensor-pairing.md).

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
  `GET /scans/{id}/export`, and the `payload` of `GET /commands` (which
  embeds the config as `scanner_config`, `config` and
  `context.scanner_config`). The structure, the non-secret
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
name. It is the only results path (protocol v1 ingest is retired). The wire vocabulary
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
budget shared with v1), per-sensor rate and per-tenant in-flight cap (`429`,
with a `Retry-After` of the refused bucket's refill time plus up to 50 %
jitter, at least 1 s and at most 5 min, so refused sensors spread their
retries); `Content-Type` (`415` + `Accept`); `Content-Encoding` gzip/zstd, one coding
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
the report's tool is one the sensor reported installed (`422
tool-not-permitted`; a sensor that reported no tool may report no result,
reserved names such as `pentest` never), at most 8 open reports per sensor
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
- **Default-branch auto-resolve needs a proven run.** Only a
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
  report never close a finding (decision O11); the per-branch
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
  state change), `enforce` (closes them as `auto_fixed`, `fixed` / `covered_scan`,
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

v2 responses carry `OpenCTEM-Protocol: 2`.

### Configuration and metrics

| Setting | Default | Meaning |
|---|---|---|
| `SENSOR_PROTOCOL_V2_RESULTS` | `true` | Mount `/api/v2/sensor`, process v2 jobs, advertise on the heartbeat. `false` unmounts it; v2 jobs already queued wait until it is on again. |
| `SENSOR_V2_BLINDING_RATIO` | `0.5` | Blinding guard ratio. |
| `SENSOR_V2_BLINDING_MIN_FINDINGS` | `100` | Blinding guard floor. |
| `INGEST_COVERAGE_AUTO_RESOLVE` | `dry_run` | Coverage-scoped auto-resolve of non-repository findings: `off`, `dry_run` or `enforce`. Keep `dry_run`: enforcement is postponed until the closure evaluator ships (decision D-22); this path cannot see template, port or authentication coverage. |
| `INGEST_MAX_PENDING_PER_TENANT` | `100` | Queue depth per tenant. |

Migrations 000237 (`ingest_reports`, v2 columns on `ingest_jobs`) and 000239
(per-report item totals). Metrics: `ingest_v2_requests_total{route,method,outcome,problem}`,
`ingest_v2_bytes{stage=encoded|decoded}`, `ingest_v2_items_total{kind,result}`,
and `ingest_v2_reports_total{state,auto_resolve}`. Every label comes from a
closed set.

## Protocol v3 (gRPC + mTLS, Connect/HTTPS fallback)

[RFC-059](../rfcs/RFC-059-sensor-transport-v3.md); state and how to work on
it: [sensor-transport-v3.md](sensor-transport-v3.md). One proto
(`openctem.sensor.v3.SensorService`) whose RPCs map one to one onto the v2
resources below and are served through the same v2 handler chain; v2 stays.

## Protocol v2 control plane

[RFC-029](../rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md). Every
other sensor resource under `/api/v2/sensor`, in the same route group and
behind the same sensor-key authenticator as the results. Identity is the key
only: no `X-Agent-ID` (the API never read it). A tenant-less (platform)
sensor gets `403 scope-denied`. Each handler calls the same application
service the retired v1 route called; only the wire differs. Bodies are JSON, decoded leniently (unknown
members ignored; at most 1 MiB, 4 MiB for `complete`, 8 MiB for the
fingerprint queries); errors are RFC 9457 problems; every response carries
`OpenCTEM-Protocol: 2`.

| Retired v1 route | v2 | Notes |
|---|---|---|
| `POST /api/v1/agent/heartbeat` | `POST /api/v2/sensor/heartbeat` | Same body. The doorbell is always on: `sensor_id`, `tenant_id`, `status` (`ok`/`paused`), `pending_jobs`, `next_heartbeat_seconds`, `actions`, `config_version` are always present. A disabled sensor gets `200` `paused` + `["pause"]` here, can still read `GET /hello`, and gets `401` everywhere else. |
| `GET /api/v1/agent/commands?limit=n` | `GET /api/v2/sensor/commands?limit=n` | `{"commands": [...]}`; a command carries `sensor_id` (null while unassigned). |
| `POST …/commands/{id}/acknowledge` | `POST /api/v2/sensor/commands/{id}/claim` | |
| `POST …/commands/{id}/start` | `POST /api/v2/sensor/commands/{id}/start` | |
| `POST …/commands/{id}/complete` | `POST /api/v2/sensor/commands/{id}/complete` | `{"result": …}` |
| `POST …/commands/{id}/fail` | `POST /api/v2/sensor/commands/{id}/fail` | `{"error_message": "…"}` |
| `GET /api/v1/agent/suppressions` | `GET /api/v2/sensor/suppressions` | Strong `ETag`; `If-None-Match` → `304`. |
| `POST /api/v1/agent/ingest/check` | `POST /api/v2/sensor/fingerprints/check` | ≤ 50,000 fingerprints (`422 too-many-items`). Answers within the sensor's [lookup reach](#lookup-reach-fingerprints-baseline-diff-suppressions). |
| `POST /api/v1/agent/ingest/baseline-diff` | `POST /api/v2/sensor/fingerprints/baseline-diff` | ≤ 50,000 fingerprints. A repository outside the sensor's lookup reach answers as unknown. |
| `POST /api/v1/agent/renew` | `POST /api/v2/sensor/keys` | `201`, `Cache-Control: no-store`; per-sensor renewal budget (burst 5, then one every 2 minutes). |
| `POST /api/v1/agent/ingest`, `/ingest/ctis`, `/ingest/chunk`, `GET /ingest/jobs/{id}` | `/api/v2/sensor/results/…` | RFC-026. |

Removed without a v2 successor: `/ingest/sarif`, `/ingest/recon`,
`/ingest/scan` (sensors convert to CTIS client-side), `/ingest/scanners`,
`/scans` (scan sessions), `/telemetry-events` (SIEM inbound) and
`/credentials/ingest` (administrators still import credentials through
`/api/v1/credentials/import`). `/api/v1/validation/evidence` is not under the
v1 mount and is still served.

**Transitions are idempotent** (`command.Service.Transition`). Repeating the
transition that produced the command's current state, by the same sensor
with the same body (a semantically equal `result`, the same stored
`error_message`), answers `200` with the command and runs no side effect
(pipeline progression, validation evidence, simulation finalisation run on
the real transition only). A different body is `409 transition-conflict`.
Any other state is `409 invalid-transition` with `"state"` (a pending
command past its expiry reads `expired`); a lost claim race is `409
command-claimed`; another sensor's or tenant's command is `404
command-not-found`. The state rules and the atomic claim live in the command service.

**Hello** lists `results` plus the control features (`heartbeat`,
`commands`, `suppressions`, `fingerprints`, `keys`). `deprecations` is
empty.

### Protocol telemetry

Every heartbeat records the protocol it arrived on and the client's
`User-Agent` (printable ASCII, ≤ 256 bytes) in `sensors.protocol_version`,
`protocol_client` and `protocol_seen_at` (migration 000248), in the
heartbeat update that already runs. `GET /api/v1/sensors` and
`GET /api/v1/sensors/{id}` return

```json
"protocol": {"version": 1, "user_agent": "openctem-sdk-go/0.8.1", "seen_at": "2026-10-02T09:00:00Z", "deprecated": true}
```

or `null` before the first heartbeat that recorded it. A `1` is left from a
heartbeat before protocol v1 was retired: that sensor can no longer connect
and must be upgraded to v0.9.0 or later.
`sensor_protocol_requests_total{protocol, route}` counts every sensor request
by protocol and route name (closed sets).

## Sensor-reported capabilities

[RFC-029 §4.3.1](../rfcs/RFC-029-sensor-protocol-v2-and-sdk-stability.md).
The heartbeat can carry what the sensor really has: `tools`
(`[{name, kind, version, installed, capabilities, content}]`), `capabilities`,
`max_concurrent_jobs`, `os` and `arch`. Each tool's `capabilities` (sdk-go
v0.13+) says what that tool serves besides its name (`nuclei` → `dast`,
`validate:nuclei`), so the flat list can be traced to a tool; `kind` is
`scanner` or `collector`. Both are sanitized like the flat list (known names
only, at most 32 per tool) and kept in `reported_tools`. The sensor's report is the truth. The administrator's
`capabilities` and `max_concurrent_jobs` on the sensor are **limits** that can
only narrow it; the tools have no limit on the sensor (the sensor grant,
`sensor_grants.tools`, narrows them at admission, RFC-052):

- effective tools = the reported installed tools (none before the first report)
- effective capabilities = reported ∩ `capabilities` (empty `capabilities`: all reported)
- effective concurrency = the smallest of the reported ceiling
  (`max_concurrent_jobs`), the administrator's `max_concurrent_jobs` and the
  reported slots (`capacity.slots_total`, see "Load, capacity and release")
  that is set (RFC-033 §6.1)
- not reported (old SDK): the administrator's capabilities and concurrency,
  and **no tool**: dispatch sends such a sensor no tool job (see below)

Storage (migration 000253): `reported_tools` (jsonb), `reported_tool_names`,
`reported_capabilities`, `reported_max_jobs`, `reported_os`, `reported_arch`,
`reported_at`, and the generated columns `effective_tools`
(`COALESCE(reported_tool_names, '{}')`, migration 001149, which dropped the
stale declared `sensors.tools`), `effective_capabilities`
(`sensor_effective_list(declared, reported)`) and `effective_max_jobs` (000257,
`sensor_effective_max_jobs(admin, reported, capacity)`). Every dispatch query reads the
`effective_*` columns: selector, `ClaimJob`, tool and capability
availability, list filters and platform capacity. The command poll's capability
gate and the API use `Sensor.EffectiveCapabilities()` and the other
`Effective*` methods (`pkg/domain/sensor/reported.go`).
`sensor_reported_caps_db_test.go` (postgres) checks that the columns and the
methods agree across a matrix of inputs.

RFC-030's tool gate on the command poll, the claim, the doorbell count and
the zone predicate (`sensorDispatchTools` in `command_repository.go`) reads
the sensor's **verified** tools: `effective_tools`, none when it never
reported. The selector, `FindAvailableWithTool`,
`HasSensorForTool` (the trigger's availability check) and
`GetAvailableToolsForTenant` use the same expression. A command that names a
tool reaches only sensors whose own probe found it installed; a sensor that
never reported gets no tool work (a tool typed at creation used to get it, and
failed with "scanner not found"). Tool-less and
capability-scoped commands are unaffected.

**Capacity vs slots** (total capacity vs what is allocatable now). The reported
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

### Tool contracts

A tool ported to the tool contract (sdk-go `docs/rfcs/sensor-sdk-v2.md`)
appears in the manifest with `contract: {api_version, digest, version, class,
tier, network, consumes, produces}`: its `tool.yaml` manifest by digest, with
the fields the platform plans and binds output with.

- **Validated whole** (`sensor.SanitizeToolContract`): `api_version` must be
  `openctem.io/tool/v1`; the digest `sha256:<64 hex>`; class, tier and
  network from their closed sets (T2 only for `target-scan`); at most 64
  consumes and 64 produces entries, each matching its grammar. One bad member
  drops the contract (the tool stays) and the manifest's `ignored` list says
  why (`invalid-contract`). The 256 KiB manifest cap bounds the rest.
- **Stored inside the manifest version** (`sensor_manifests.manifest`), so it
  is content-addressed by the manifest digest, kept per sensor and read only
  under the sensor's tenant. There is no table shared across tenants: a
  digest one tenant's sensor reports is never visible to, or reused for,
  another tenant. A changed contract digest is a manifest change
  (`contracts` in the diff, "tool contract of N changed" on the timeline).
- **Used by ingest** to narrow what a command-bound report of that tool may
  carry ([scan-stages.md §4](scan-stages.md#4-report-output-type-binding-decision-g12)).
  A contract only narrows: it comes from the sensor.
- **Shown** on the sensor drawer's Manifest tab (class, tier, network,
  consumes, produces, digest) and returned by
  `GET /api/v1/sensors/{id}/manifest[s]`.
- **Tool options.** The stored descriptor carries the tool's configuration
  schema (`config`, the closed JSON Schema subset of the CTIS settings
  contract, `github.com/openctemio/ctis/settings`). The Manifest tab lists
  each tool's options read-only under "Options (N)": common options first
  (`x-octm-common`: `timeout`, `rate`, `concurrency`, `retries`, defined
  once in `ctis/tooloption`), then the tool's own, each with its default,
  range or values, who may set it (`x-octm-scope`: the sensor's
  configuration only, or a scan too), its safety class (`x-octm-tier`: T0
  safe, T1 impact, T2 dangerous) and the native flag it maps to
  (`x-octm-flag`). The web reads the descriptor with a checking reader
  (`web/src/features/sensors/lib/tool-options.ts`): malformed parts are
  skipped, at most 64 options and 500 characters per text are shown, and
  every string renders as text. Common option names and the built-in
  tools' option titles are translated; a third-party tool's own text shows
  as the sensor reported it.

**Derived manifests.** For a heartbeat without `manifest_digest` that carries
tools (protocol v1, older SDKs), the platform builds the manifest from the
sanitized report. Its sensor-wide capabilities are the flat ones no installed
tool provides. The platform stores it with `source = heartbeat` only when its
digest differs from the current one. Every sensor therefore gets a version
history, and a steady heartbeat writes nothing extra. The comparison uses the
digest in the row the heartbeat already reads.

**Phase 2** (RFC-033 §6.12, decisions O1–O4):

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


### Tool availability

The Tools page, the scan builder and the workflow step pickers read the tools of the current manifests through one view, `GET /api/v1/tools?include=availability`. It joins them with the catalog per tenant and derives a status per tool: ready, no_sensor, offline_only, outdated or disabled. See [tool-availability.md](tool-availability.md).

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
- **Grant and trust.** Its reports name no command, so they pass the push
  ingest gate (`internal/app/ingest/quarantine.go` `admitPush`), which needs
  two things: push ingest in the sensor's grant, and trust level `trusted`
  (`Grant.Effective()` turns push ingest off for any sensor that is not
  trusted).
  - *Grant.* A sensor created with type `collector` (create API or pairing
    approval without a chosen profile) gets the `collector` profile:
    `collect` and `connector_sync` jobs, passive tier, no target network,
    push ingest on (insert trigger `sensor_grants_default`, migration
    002075; `sensor.DefaultProfileFor`). Sensors created before that keep
    their grant; a collector still on `internal-network-scanner` needs its
    profile changed to `collector` on its Grant.
  - *EASM sensors.* A sensor created with type `sensor` gets
    `easm-external` (public targets only, migration 002084). Sensors still
    on `legacy-broad` get a one-click narrower profile on their Grant,
    suggested from their last 30 days of jobs
    ([sensor-pairing.md](sensor-pairing.md#leaving-the-legacy-grant)).
  - *Trust.* Trust is never automatic. A new collector starts at trust level
    `new`, and every report is refused until an administrator promotes it,
    either on the sensor's Grant (**Promote to Trusted**) or at creation
    with the checkbox **Trust this collector to push asset reports**
    (`POST /api/v1/sensors` with `"trusted": true`). The checkbox is off by
    default, applies to type `collector` only (400 otherwise) and needs
    `sensors:grant:widen` like any promotion; that is checked before the
    sensor is created, so a refusal creates nothing. The promotion is
    audited at high severity (`sensor.grant_changed`) and notifies every
    administrator. If it fails after the sensor exists, the response says
    `"trusted": false` and the sensor stays `new`.
  - *Refusal.* A refused report gets error code `PUSH_INGEST_NOT_GRANTED`
    (protocol v2 item error `push_ingest_not_granted`), whose message names
    what is missing: the grant (`ingest.ErrPushIngestNotGranted`) or trust
    (`ingest.ErrPushIngestUntrusted`). The sensor timeline event and the
    `sensor.push_refused_grant` audit entry carry `missing: grant|trust`,
    and the sensor's Grant section in the console explains the refusal for
    a collector and links the fix.
  - Once admitted, a collector report may create assets but never change an
    existing one, and scope exclusions apply (see the result binding
    section below). The exception: a complete report (`coverage_type:
    full`) of a trusted collector may change the assets its own collector
    source created and marks the ones it no longer lists as not seen
    (RFC-040 §12; [sensor-result-binding.md](sensor-result-binding.md)).
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

### What ingest makes of a collector report

The fields each collector sends are listed in the collector's
`docs/DATA.md`. Ingest uses them as follows; every lookup and write stays
inside the reporting organization.

| Report data | Stored as | Rule |
|---|---|---|
| `relationships` (CTIS) | Asset relationships | `hosted_by` becomes `runs_on` (a virtual machine on its hypervisor host) or, for an address, the host `contains` it; `subdomain_of` is stored parent first; the other types keep their name. Only pairs the relationship registry allows; only when the report may change the edge's source asset (`report_relationships.go`). |
| `esxi_host` on a virtual machine | `runs_on` edge to the hypervisor host | The host must be in the report or already in the organization. The vSphere cluster and datacenter stay properties: there is no asset type for them. |
| `ip_addresses` on a host | `contains` edges to address assets | Only to address assets that already exist, at most 32 per host; addresses are never created from a host's properties. |
| `ad_object_guid` | Identifier `directory_object_id` | Strong and single-valued: a computer renamed or moved in the directory stays the same asset ([asset-identity-resolution.md](asset-identity-resolution.md)). The vCenter instance UUID is the `cloud_id` identifier. |
| `last_seen` | The asset's last-seen time | Only when earlier than the report and not before 2000; it never moves the stored time backwards, and an older observation never reactivates a stale asset (`last_seen.go`, `Asset.ObserveAt`). |
| `owner` (mail or UPN) | `owner_ref`, then a primary owner | A trusted collector is an `integration` source, so its owner claim is used under the reconciliation policy; an untrusted one's is dropped. The owner-resolution job names only an active member of the organization whose email matches; an unknown owner stays text and nobody is invited. An owner never grants data access. |
| `zone_visibility: private` on a DNS name | Exposure `private`, not internet-accessible | Also a root domain that only private-zone names name (`private_zone.go`). |
| A network device's address (PRTG, Splunk) | Matched to the existing device | Network devices only (not segments, hosts or address assets), in the IP trust window, one candidate only ([asset-identity-resolution.md](asset-identity-resolution.md)). |
| `coverage_type: full` from a trusted collector | Refresh of its own assets, unlisted ones marked not seen | RFC-040 §12, [sensor-result-binding.md](sensor-result-binding.md). Partial and incremental reports keep the unsolicited limits and never mark anything. |

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

## The shared claim path

A shared sensor (scope `instance`) claims shared jobs (`is_platform_job`) of
every organization; it is the only way a shared job is handed out
([RFC-100](../rfcs/RFC-100-shared-sensors.md) §8, RFC-090 W11). Code:
`internal/infra/postgres/command_shared_claim.go`,
`internal/app/command/shared_claim.go`, `sensor_control_v2_handler.go`.

**Who.** The authenticated sensor's stored row decides, never a request
field. It must be an active shared sensor (no tenant) that **reported**
`shared.isolation@1` (the sdk-go shared isolation profile: per-job sandbox,
network namespace, egress policy) and accepts unzoned jobs
(`sensors.accepts_unzoned_jobs`, default true; false keeps a shared sensor
for zone work only). An organization sensor never takes a shared job
(`tenantJobPredicate`) and a shared sensor never takes anything else.

**What.** A pending, unheld, unexpired, due, **unzoned** shared job whose
tool the sensor verified (`effective_tools`), whose required capabilities it
advertises and whose required features it reported, not refused by it, and
whose `preferred_region` (payload) is empty or the sensor's `region`. Its
hosts must be free in its organization: the same host keys, advisory locks
and settled-host rule as the organization's own sensors, so a shared job and
an organization sensor's job never take one host at once.

**Order.** Priority class (one class up per 30 minutes waited, never into
critical), then the organization with the fewest shared jobs in flight
(fair share), then queue priority and age.

**Limits.** Each organization's `platform_scans_concurrent` limit, read
through the entitlement service by key: in the claim transaction, per
organization, a lock on its shared jobs, a count of those in flight, and no
more than the limit; an organization at its limit is skipped and its jobs
wait. A limit that cannot be read counts as 0 (fail closed). Without the
entitlement service the shared claim hands out nothing.

**Access.** The access policy of RFC-100 §5 (`SharedSensorsAllowed`: the
instance switch, the administrator's decision, the organization's opt-out)
is applied again at claim time: an organization that lost access or opted
out after queueing is skipped, and its jobs wait and expire. Without the
policy wired the shared claim hands out nothing.

**Gates.** Each organization's candidates pass the same gates as an
organization sensor's claim, in that organization: the shared sensor's grant
(it has no tenant; without a reader for it, or without the grant, nothing is
claimed), its manifest and local policy, the scope re-check, scan
windows, program rules and tool settings. Scans are capped at the sensor's
free slots.

**Claim.** `commands.sensor_id` is the holder of a shared job, as for every
job, with a lease and a new lease epoch; the claim is signed for the shared
sensor in the command's organization (statement `tenant_id` = the command's,
`sensor_id` = the shared sensor). `commands.platform_sensor_id` is removed.

**Routes.** On `GET /api/v2/sensor/commands` a shared sensor must claim
(capacity feature, claim-N); a listing poll answers 403 `scope-denied`.
Claim by id (a replay), start, complete, fail, release and logs work only for
a shared job it holds; the step runs in the command's organization, read
from the command. Complete, fail and logs need `X-OpenCTEM-Lease-Epoch`.
Anything else answers `command-not-found`. Its heartbeat renews the leases
of the shared jobs it lists and holds, records their progress per
organization, and lists every other id to cancel; the answer names no
tenant. The other control routes (manifest, config report, suppressions,
fingerprints, key renewal, content) still refuse a shared sensor.

**Reapers.** The lease reaper, the stall reaper and the stuck-job recovery
treat shared jobs like the others. A shared job still queued 60 minutes
after it was queued, or after it last went back to the queue, expires.

**Gate.** No shared job is created, and none is claimed, until the access
gate opens (`SharedSensorsAllowed` answers false, RFC-100 §11).

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
  - **Routed scan work** (type `scan` with a `scan_run_id`, the same rule
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

### Task budgets, progress and stalls

A lease says the sensor is alive; it does not say the task is getting
anywhere. Each scan command carries a layered budget in its payload
(`budget`: `target_seconds`, `task_seconds`, `stall_seconds`;
`pkg/domain/toolbudget`), from per-tool defaults:

- **Per target.** The sensor passes `target_seconds` to the tool as its own
  per-request timeout and bounds each target with it (sdk-go
  `core.RunPerTarget`). A target over its budget is that target's reach
  `timeout`; the other targets go on.
- **Per task.** `task_seconds` = overhead + ceil(targets / concurrency) ×
  per-target budget, within 5 min – 24 h. The sensor stops the task at
  twice that (an explicit step `timeout_seconds` still wins).
- **Progress.** A sensor on a platform that lists `command_progress` sends
  `progress: {<command id>: {done, total, finished}}` on every heartbeat
  (`finished`: inclusive index ranges into the command's target list, for
  settling targets one by one later; not stored yet). The platform
  records it only for commands that sensor holds (tenant, sensor, state),
  bounds it by the command's own target count, never lets `done` go down
  within a claim, and moves `last_progress_at` only when `done` grows. A
  new claim starts with no progress.
- **Stall and overrun** (`JobRecoveryController`, every minute): a running
  command with a budget is re-queued (one more dispatch attempt, like a lost
  lease) when its sensor reports progress and either targets remain and
  none finished for `stall_seconds`, or it ran past 2 × `task_seconds` +
  5 min. A slow but progressing task is never re-queued before that. A
  sensor that reports no progress predates budgets and is bounded only by
  its lease and the run's cap. Metric
  `commands_stalled_total`.
- **Trust.** Progress is a liveness hint, never authority: faked progress
  only defers the stall check, never the overrun or the run's 24 h cap.
- The run page shows each task's `done/total`, its budget and how long
  since a target last finished.

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
  `kill_switch`, `warnings` and `required`. Older SDKs send nothing.
  `required: true` with `state: absent` is a new install that fails closed
  (it refuses every job with a network target, custom templates and
  callbacks, rule `no_local_policy`); `required: false` with `absent` is a
  legacy install that admits them (RFC-040 §11.4 Q3 revised). The config
  report's `policy.local` check then fails with code `required_absent`; the
  checklist derived for a sensor without a config report does the same.
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
- **Structured refusal and re-queue** (D8; migration
  001046). Hello feature `refusal`: v2 `POST /commands/{id}/fail` accepts
  `refusal: {layer, rule, detail}` (layer from a closed set: `builtin`,
  `local`, `managed`, `scope`, `platform_tool_gate`; sanitized like the
  report). Without it a reason starting `refused by local policy: ` still
  counts (older SDKs, protocol v1). For **routed work** (a scan command with a
  `scan_run_id`, the work the platform chose a sensor for; the rule the
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
- **Per-target refusals** (sdk-go #191). A scan target the local policy
  refuses, or cannot check, no longer refuses the whole job. "Cannot check"
  means the name does not resolve or the target is a wildcard pattern. The
  sensor removes the target before any tool sees it, runs the job on the rest,
  and completes the command with `result.metadata.refused_targets`,
  `refused_targets_total` and `partial: true`.
  - The platform reads them when the command completes
    (`pipeline.ParseSkippedTargets`: at most 20 listed, each string cleaned to
    one bounded line, unknown reasons read as `refused`).
  - The step ends `partial` with code `TARGETS_SKIPPED` and a summary, so the
    run ends `partial`. For a batched step, the skipped counts of the completed
    batches are summed (`StepBatchState`).
  - The task's `skipped_targets` / `skipped_targets_total` show under its
    status as "Completed with N targets skipped: … (does not resolve)".
  - Skipped targets do not roll over to the next scheduled run; the sensor
    would refuse them again.
  - A job whose every target is refused still fails (and is re-queued as
    above when it is routed work).
- **Unreachable targets** (RFC-089 §4.7).
  A sensor reports per-target reach in `result.metadata.reach` (`targets`,
  `reached`, `unreached`, `classes`, per-block rows) and the unreached ones in
  `unreached_targets` / `unreached_targets_total` (classes `no_route`,
  `firewall_refused`, `timeout`, `dns_failure`; a closed port counts as
  reached).
  - The platform reads them when the command completes
    (`scanrun.ParseReach`, `ParseUnreachedTargets`: counts clamped, at most 20
    listed, every string cleaned to one bounded line, unknown classes
    dropped).
  - None reached and no findings: the step **fails** with
    `TARGET_UNREACHABLE` (class `placement`, never retried) instead of
    completing with zero results. Some unreached: the step ends `partial`
    with code `TARGET_UNREACHABLE` and a per-class summary (`TARGETS_SKIPPED`
    keeps precedence when targets were also skipped).
  - Batched steps sum the completed batches' reach (`StepBatchState`); the
    step fails only when every batch reported reach and none reached a target.
  - A result without `reach` (an older sensor) keeps today's outcome; its
    failure text (`target_unreachable`, `network is unreachable`, `no route
    to host`, `host is unreachable`) is classified as `TARGET_UNREACHABLE`,
    and a sensor may send that code in a structured fail.
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
- **Dispatch pre-check**. One function,
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
  allows both opt-ins, decision Q4 (a)). The same check runs in three
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
- **Organization opt-ins, default off** (D3, D9). Security
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
- **Console** (web). The fleet table has a Policy column and a "Local policy"
  facet (`?policy=enforced|absent|paused|unknown`; "absent" + "unknown" is "no
  local policy"). The detail sheet shows the full reported digest (selectable)
  and, for a sensor without a policy or one that repeats the absent-policy
  warning, the corrected guidance: custom templates need
  `SENSOR_TEMPLATE_SIGNING_KEYS` on the host and an organization opt-in;
  interactsh runs only when a job asks for it and the organization allows it.
  Settings → Authentication and security has the two opt-in switches; the
  Scans page and the settings show a banner listing the scans the switches
  affect (`GET /scans/sensor-opt-in-impact`). Trigger refusals
  `SENSOR_POLICY_REFUSED` and `SENSOR_OPT_IN_DISABLED` carry a next-step hint.
- **Install dialog.** `GET /sensors/{id}/config-templates` returns `policy`, a
  sensor-policy/v1 template (`configs/sensor-products/sensor/policy.tmpl`)
  prefilled with the ranges of the sensor's scan zones (none for a sensor in
  the default zone, which scans public targets), tools from the sensor, and
  custom templates and interactsh off. The docker, Compose and Kubernetes
  snippets mount it read-only and require it (`SENSOR_LOCAL_POLICY`), set
  `SENSOR_ALLOW_PRIVATE_TARGETS=1` when a zone range is private, and run the
  sensor hardened (read-only root filesystem, all capabilities dropped, no
  privilege escalation, seccomp RuntimeDefault, writable tmpfs/emptyDir
  scratch directories). The Helm snippet turns on `sensor.localPolicy` of
  chart 0.11.0.

## Security posture (RFC-040 §11.4)

Existing sensors without a local policy, without a pinned platform CA, or
running tools without network confinement keep working, but they are flagged
prominently: on the manifest, on the Sensors page and with an alert (owner
decisions Q3 revised, Q10, Q12, 2026-10-08).

- **Hello feature `posture`.** Listed when manifests are served. SDKs that see
  it add the manifest member `posture`: `platform_tls.pin` (`fingerprint`: the
  CA pinned by `SENSOR_CA_FINGERPRINT`; `ca_file`: a private CA file besides
  the system trust store; `none`: the system trust store only) and `sandbox`
  (`mode` `off`/`auto`/`required`, `sandboxed`, `network_enforced`). The gRPC
  transport pins its own CA; `platform_tls.pin` is about the HTTPS client.
- **Storage.** The sanitized manifest (`sensor_manifests.manifest`, no new
  column): `sensor.SanitizeManifestPosture` keeps closed values only; an
  unknown pin is dropped, an unknown sandbox mode is cleared.
- **Read side.** `GET /sensors` and `GET /sensors/{id}` return `posture`:
  `local_policy` (`enforced`, `absent_required`, `absent_legacy`, `unknown`,
  from `sensors.reported_local_policy`), `platform_pin` (`fingerprint`,
  `ca_file`, `none`, `unknown`) and `network_enforced` (`true`, `false`,
  `null` when not reported), both from the current manifest (the row whose
  digest is `sensors.manifest_digest`, read in the same query with a
  correlated lookup on the `(sensor_id, digest)` index, the manifest's tenant
  matching the sensor's), and `unhardened`, the reasons, in order:
  - `policy_none`: `absent_legacy`, or `unknown` for a sensor that has
    connected (an SDK that ignores local policies);
  - `pin_none`: `platform_pin` is `none`;
  - `network_unenforced`: `network_enforced` is `false`;
  - `bearer_key`: the sensor authenticates with a bearer key instead of a
    key-bound identity (and has connected).

  An unreported pin or sandbox is not flagged. `sensor.DerivePosture` is the
  one derivation, used by the API and the metric.
- **Console.** An "Unhardened" warning tag on the Sensors list rows, the phone
  cards and the detail header (the title lists the fixes), and a Security
  posture block in the detail sheet with one fix per reason: install a local
  policy (the Local policy tab of the install commands), pin the platform CA
  with `SENSOR_CA_FINGERPRINT`, run with `SENSOR_SANDBOX_NETWORK=required` and
  the seccomp profile, pair again for a key-bound identity.
- **Alert.** Gauge `openctem_sensors_unhardened{kind}` (`policy_none`,
  `pin_none`, `network_unenforced`, `bearer_key`): active tenant sensors by
  reason, platform-wide, no tenant or sensor label. Alert `SensorsUnhardened`
  (warning, `for: 24h`); runbook in
  [operations/monitoring.md](../operations/monitoring.md#sensorsunhardened).

The posture is a claim from the sensor: it is shown and alerted on, and never
relaxes a platform check (dispatch, scope, job signing, authentication). A
sensor that reports a strong posture gets no more work than one that reports
none.

## Config report: the setup checklist

> Design: [RFC-033 §11](../rfcs/RFC-033-sensor-manifest.md)
> (sensor config doctor) P0. Operators: [Fix a sensor's setup checklist](../how-to/fix-sensor-setup-checklist.md).

A sensor runs preflight checks on itself and sends the results with
`PUT /api/v2/sensor/config-report` (hello feature `config_report`, at most
64 KiB). Its heartbeat carries `config_report.digest`, the digest the
platform returned; a different digest gets the action `send_config_report`.

- **Sanitized, never trusted** (`pkg/domain/sensor/config_report.go`): closed
  sets, typed and re-validated params, depth ≤ 6, ≤ 200 checks, bounded
  plain text, unknown members dropped and listed in `ignored`. Settings keep
  name, set, source, secret and valid only; a value is never stored.
- **Stored** (migration 001061): the latest report per sensor in
  `sensor_config_reports` (tenant-scoped), `sensors.config_report_digest` and
  `config_health` (the platform's rollup: ok, attention, impaired, blocked),
  and `sensors.config_heartbeat_digest`, written by every heartbeat. The two
  digests differ when the stored report is stale.
- **Health**: `config_check_failed` (any fail or error), `config_check_warning`
  (a warn of severity warning or above), `config_report_stale` (online, and
  the heartbeat echoes another digest or none). A stale report raises only the
  stale reason. The list and detail responses carry `config_health`.
- **Read**: `GET /api/v1/sensors/{id}/config-report` (`sensors:read`, 404 for
  another tenant). Each check is explained from the platform catalog
  (`internal/app/sensor/config_check_catalog.go`): group, title, why, fix
  snippets for env, compose and helm with the check's values escaped per
  format, and a docs link. Sensor text (`summary`, `excerpt`) is data, shown
  as plain text. Sensors without a report get a checklist derived from the
  heartbeat (`state: derived`): tool install states, `tools.available`,
  `policy.local`.
- **No dispatch change** in P0: a report only informs.

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

## Tool settings (RFC-038)

> Design: [RFC-038](../rfcs/RFC-038-sensor-tool-settings.md). Status:
> **organization tool defaults, per-sensor overrides, per-scan settings, the
> scan-layer preview and the save-time check of scan and step options
> shipped** (below); dangerous-option enablement is planned.

**Layers.** A tool's value comes from the first of these that sets it,
reading upward:

```
tool default (the manifest's settings schema)
  → organization default   (Settings → Scanning → Tool defaults; may raise or lower)
  → sensor override        (sensor drawer → Tool settings; may raise or lower)
  → scan profile / workflow step / scan   (scope "scan" keys; lower-only for rate, concurrency, retries)
  → job decision           (the platform's budget, fitted under the value in force)
  → sensor local policy    (on the sensor, last; only narrows)
```

The organization layer is a default, not a cap: a sensor overrides a key in
either direction. Only the two administrators' layers may raise rate,
concurrency or retries above the tool's default.

**Organization tool defaults (shipped).** An owner or administrator sets,
per tool, the values every one of the organization's own sensors runs the
tool with, from Settings → Scanning → Tool defaults.

- *Schema.* The tools listed are those that a current manifest of the
  organization's own sensors declares settings for (never a platform
  sensor). The form uses the reference schema, which is the one from the most
  recently reported manifest.
- *Validation.* A save is validated against **every** distinct schema the
  organization's sensors report for the tool (at most 200 sensors, one per
  schema digest), as a tenant layer (`ValidateTenantToolSettings`). A
  value one sensor's tool version refuses is a 422 whose message names that
  sensor. A non-default dangerous (T2) value is refused.
- *Storage.* Table `tenant_tool_settings` (migration `002136`): `tenant_id`,
  `tool`, `values`, `schema_digest` (of the reference schema), `updated_by`,
  `updated_at`; primary key (`tenant_id`, `tool`); foreign key to `tenants`
  with `ON DELETE CASCADE`.
- *Audit.* Saving and resetting log `settings.updated` on the organization
  (`resource_type` `tenant`, resource name `tool defaults: <tool>`) with one
  change per key (`tool_settings.<tool>.<key>`), redacted like the
  sensor's. A change that sets an Impact option is high severity.
- *Problems.* Defaults that a sensor's schema refuses (a sensor joined or was
  upgraded with an older or narrower tool) are listed per sensor on the page
  and in that sensor's Tool settings tab. That sensor's jobs of the tool fail
  with `TOOL_SETTINGS_INVALID` until the defaults change. They are never
  silently dropped.

**Impact options need step-up.** Setting an `x-octm-tier: T1` (Impact) key
to a new value, in either the organization or the sensor layer, needs the
acting user's recent re-authentication (403 `STEP_UP_REQUIRED`;
docs/architecture/step-up-reauth.md). Removing such a value does not.
`sensors:write` is reserved for the owner and admin roles, which hold every
permission, so a separate permission would add no control. Step-up is the
control.

**Per-sensor overrides (shipped).** An owner or administrator overrides the
organization's defaults for one of the organization's own sensors from the
sensor drawer's "Tool settings" tab. Each option shows its effective value
and its source (tool default, organization or this sensor).

- *Schema.* The settings schema is the `config` object of the tool's
  descriptor (Tool Contract v1), which the sensor already reports in its
  manifest and the platform stores in the sensor's current manifest version
  (tenant-scoped). It is parsed with the CTIS settings contract
  (`github.com/openctemio/ctis/settings`, `ParseSchema`): a closed JSON Schema
  subset with `x-octm-*` annotations (scope, tier, common option, native
  flag, sensitive, group). A descriptor without `config` means the tool has
  no settings; a schema the contract refuses is ignored (logged). There is
  no upload route: the schema always comes from the sensor's own manifest.
- *Storage.* Table `sensor_tool_settings` (migration `002114`): `tenant_id`,
  `sensor_id`, `tool`, `values` (jsonb), `schema_digest` (the digest of the
  schema the values were validated against), `updated_by`, `updated_at`;
  primary key (`sensor_id`, `tool`); foreign key (`tenant_id`, `sensor_id`) →
  `sensors` with `ON DELETE CASCADE`, so a row always belongs to a sensor of
  the same organization and a platform sensor (no tenant) can hold none.
  Every query carries the tenant.
- *Validation.* A save is validated with `Schema.Validate` and
  `Schema.Resolve(Layer{Source: SourceSensor})`: unknown keys, wrong types,
  values outside bounds or enums and sensitive keys are refused, with every
  problem by JSON pointer (422). A non-default value of an `x-octm-tier: T2`
  (dangerous) key is refused until the organization's enablement of
  dangerous options exists.
- *Audit.* Saving and resetting log `sensor.updated` with one change per
  key (`tool_settings.<tool>.<key>`, before and after). The value of a
  sensitive or write-only key, or of a key the schema no longer knows, is
  written as `[redacted]`.
- *Delivery.* When a sensor claims a scan job (claim-N, poll, claim by id;
  `internal/app/command/tool_settings.go`), the platform looks up the
  organization's defaults and that sensor's stored values for the job's
  tool and puts them into the payload as `settings_layers: {"tenant": {...},
  "sensor": {...}}` before the job is signed, so the job signature (payload
  SHA-256) covers them. `tenant` is the organization's defaults *without
  the keys the sensor overrides* (`InheritedValues`), so the two layers
  never share a key. The sensor resolves them with the unchanged settings
  contract (whose tenant layer would otherwise cap the sensor's), and its
  report names each key's source. `tenant` is added only when the claiming
  sensor is one of the command's organization's own sensors, never for a
  shared platform sensor. The organization's values are validated against
  the claiming sensor's schema on every claim. The stored command is never
  changed, and a `settings_layers` that a command's creator put in the
  payload is replaced or removed. If the sensor's current schema digest
  differs from the stored one (a sensor upgrade), the values are validated
  again; values that no longer validate fail the job with
  `TOOL_SETTINGS_INVALID` instead of running it without them (the tool
  settings list shows the problems; save or reset fixes them). A settings
  lookup that fails withholds the job (it stays pending). The sensor
  validates the layer again with its own copy of the contract, resolves it
  with the scan's own options (a scan may only lower a common option the
  sensor layer set) and clamps by its local policy.

| Route | Gate | |
|---|---|---|
| `GET /api/v1/sensors/tool-defaults` | `sensors:read` | per tool the organization's own sensors declare settings for: reference `schema`, `values`, `stored`, `sensors` (count), `problems` per sensor |
| `PUT /api/v1/sensors/tool-defaults/{tool}` | `sensors:write` (+ step-up for an Impact change) | body `{"values": {...}}`; 422 by path, naming the sensor that refuses a value |
| `DELETE /api/v1/sensors/tool-defaults/{tool}` | `sensors:write` | back to the tool's defaults; works for a tool no sensor reports any more |
| `GET /api/v1/sensors/{id}/tool-settings` | `sensors:read` | per tool with a schema: `schema`, `schema_digest`, `values`, `stored`, `problems`, `organization_values`, `organization_problems` |
| `PUT /api/v1/sensors/{id}/tool-settings/{tool}` | `sensors:write` | body `{"values": {...}}`; 422 with `details: [{path, message}]` |
| `DELETE /api/v1/sensors/{id}/tool-settings/{tool}` | `sensors:write` | back to defaults; works for a tool the manifest no longer lists |
| `GET /api/v1/sensors/{id}/tool-settings/{tool}/effective` | `sensors:read` | every key with `value`, `source` (`default`/`tenant`/`sensor`), `chain` (every layer that sets it, lowest first), `flag`, `common`, `scope`, `tier` |
| `POST /api/v1/sensors/{id}/tool-settings/{tool}/preview` | `sensors:read` | read-only; body `{"config": {...}}` (a scan's or step's options); every key with its `source` (`default`/`tenant`/`sensor`/`scan`), `chain`, and the `ignored` config keys; 422 by path when the sensor would refuse the config |

Every route on one sensor ends with the own-sensor check: another
organization's sensor and a platform sensor answer 404; the tool-defaults
routes take the organization from the authenticated context. Key files:
`pkg/domain/sensor/tool_settings.go`, `internal/app/sensor/tool_settings.go`,
`internal/app/sensor/tool_defaults.go`,
`internal/infra/postgres/sensor_tool_settings.go`,
`internal/infra/postgres/tenant_tool_settings.go`,
`internal/infra/http/handler/sensor_tool_settings_handler.go`,
`internal/app/command/tool_settings.go`; web
`web/src/features/sensors/components/sensor-tool-settings.tsx` and
`web/src/features/sensors/lib/tool-settings.ts`.

**Scan-layer preview and save-time check (shipped).** A scan's or a
workflow step's options are checked the way the sensor will resolve them
(`pkg/domain/sensor/tool_settings.go`: `ScanSettingsLayer`,
`ValidateScanSettings`). The scan layer is the config keys the tool's
schema declares, minus the keys the sensor's executor reads itself
(`rate_limit`, `concurrency`, `bulk_size` are the job's limits, which only
ever lower the value in force; `allow_interactsh`, `exclude`); other keys
are ignored, as on the sensor. Over the organization's defaults and the
sensor's stored values, the scan layer may only set `scan`-scope keys within
their bounds, may not raise rate, concurrency or retries above the value in
force (the sensor's, the organization's, or the default), and may not give a dangerous (T2) key a non-default value.

- *Preview.* `POST .../tool-settings/{tool}/preview` answers what a job of
  that config runs with on that sensor, before the job's own limits and the
  sensor's local policy (both only lower values). It stores nothing.
- *Save.* Saving a single-scanner scan (create, update) and adding or
  editing a step pinned to a tool check its options against every one of
  the organization's own active sensors that reports the tool and declares
  settings for it (at most 50): the save is refused (400, naming the
  sensor and the first problem) only when no such sensor accepts the
  options, so one stale sensor does not block a scan the others run. With
  no such sensor (platform sensors only, or a tool without settings) the
  save is not checked here; the sensor still refuses what it cannot run. A
  step that picks its tool at run time is not checked (no single schema).

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

Options a tool does not declare in its schema stay with the sensor's
wrappers (host env vars or code).

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

**What the platform does** (decisions D1–D3):

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
