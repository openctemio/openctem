# RFC-023 §9.5 — Sensor rename: API contract changes

> Companion to [RFC-023 §9.5](RFC-023-scan-zones-and-scanners.md#95-decision-update-complete-rename-supersedes-the-keep-rows-of-94).
> Scope: the API step of the complete agent → sensor rename (migration
> **000230**). This is the exhaustive list the UI follow-up, operators and
> integrators implement against. Anything not listed here did not change.

## 1. What did not change (protocol v1)

Everything a deployed sensor or SDK speaks is byte-for-byte what it was. It
lives in one package, `pkg/sensorproto/legacyv1`, and is pinned by a golden
test recorded before the rename
(`internal/infra/http/handler/protocol_v1_golden_db_test.go`).

| Surface | Kept as is |
|---|---|
| Routes | `/api/v1/agent/*` (heartbeat, renew, ingest/*, commands poll/acknowledge/start/complete/fail, scans, telemetry-events), `/api/v1/agent/credentials/ingest`, `/api/v1/validation/evidence` |
| Auth | `Authorization: Bearer <rda_ key>` or `X-API-Key` |
| Response fields | `agent_id` in the heartbeat, command and scan-session responses |
| Job payload | key `agent_preference` in command payloads |
| Error texts | `Agent not authenticated`, `Agent cannot renew`, `Platform agents require tenant context for this operation`, `Platform agents require job context for this operation`; error code `INVALID_AGENT` |
| Async ingest | `Location: /api/v1/agent/ingest/jobs/{id}` |
| Sensor `type` values | `worker`, `scanner`, `sensor`, `collector`, `runner` (and stored `agent`, `platform`) are unchanged in input, storage and output |
| Inbound labels | a CTIS asset with `discovery_source: "agent"` is accepted and stored as `sensor` |
| Released binary interface | config templates (`GET /api/v1/sensors/{id}/config-templates`) still render the current binary's settings: `AGENT_ID`, `./agent`, `agent.yaml`, image `openctemio/agent` |

## 2. Management URLs

| Before | After |
|---|---|
| `GET /api/v1/agents` | `GET /api/v1/sensors` |
| `POST /api/v1/agents` | `POST /api/v1/sensors` |
| `GET /api/v1/agents/stats` | `GET /api/v1/sensors/stats` |
| `GET /api/v1/agents/available-capabilities` | `GET /api/v1/sensors/available-capabilities` |
| `GET /api/v1/agents/{id}` | `GET /api/v1/sensors/{id}` |
| `PUT /api/v1/agents/{id}` | `PUT /api/v1/sensors/{id}` |
| `DELETE /api/v1/agents/{id}` | `DELETE /api/v1/sensors/{id}` |
| `GET /api/v1/agents/{id}/config-templates` | `GET /api/v1/sensors/{id}/config-templates` |
| `POST /api/v1/agents/{id}/regenerate-key` | `POST /api/v1/sensors/{id}/regenerate-key` |
| `POST /api/v1/agents/{id}/activate` | `POST /api/v1/sensors/{id}/activate` |
| `POST /api/v1/agents/{id}/deactivate` | `POST /api/v1/sensors/{id}/deactivate` |
| `POST /api/v1/agents/{id}/revoke` | `POST /api/v1/sensors/{id}/revoke` |

Every old route answers **`308 Permanent Redirect`** (method and body
preserved) to the new path with the query string kept, and these headers:

```http
Location: /api/v1/sensors/<same rest of path>?<same query>
Deprecation: @1790812800
Sunset: Thu, 01 Apr 2027 00:00:00 GMT
Link: </api/v1/sensors>; rel="successor-version"
```

- `Deprecation` (RFC 9745) = 2026-10-01T00:00:00Z; `Sunset` (RFC 8594) =
  2027-04-01. After the sunset the routes are removed (410 in that release).
- Each use is counted in the Prometheus counter
  `deprecated_management_path_requests_total{method}` and logged at INFO
  (`deprecated management path used; redirecting to /api/v1/sensors`, with
  method, path and user agent).
- The redirect routes are registered for GET/POST/PUT/DELETE only; `HEAD`
  is not routed (use `curl -s -o /dev/null -D - …` rather than `curl -I`).
- The redirect carries no authorization of its own: the client re-sends its
  credentials to `/api/v1/sensors`, which enforces `sensors:*`.

Other management requests:

| Endpoint | Change |
|---|---|
| `GET /api/v1/sensors/{id}/config-templates` | request header `X-Agent-API-Key` → **`X-Sensor-API-Key`** |
| `GET /api/v1/commands` | query parameter `agent_id` → **`sensor_id`** |

## 3. JSON field renames in management requests and responses

| Endpoint(s) | Before | After |
|---|---|---|
| `POST /api/v1/sensors` (response) | `agent` (object) | `sensor` |
| `GET/POST /api/v1/commands`, `GET /api/v1/commands/{id}`, `POST /api/v1/commands/{id}/cancel` (response) | `agent_id` | `sensor_id` |
| `POST /api/v1/commands` (request) | `agent_id` | `sensor_id` |
| `GET /api/v1/scan-sessions`, `GET /api/v1/scan-sessions/{id}` | `agent_id` | `sensor_id` |
| `POST /api/v1/scans`, `PUT /api/v1/scans/{id}` (request); every scan response (`GET /api/v1/scans`, `GET /api/v1/scans/{id}`, create/update/clone/activate/… responses) | `agent_preference` | `sensor_preference` |
| `GET /api/v1/scans/{id}/export` (file) | `agent_preference` | `sensor_preference` (`POST /api/v1/scans/import` still reads `agent_preference` from files exported before the rename) |
| Pipeline templates — `settings` object in `POST/PUT /api/v1/pipelines`, every pipeline template response | `settings.agent_preference` | `settings.sensor_preference` |
| `GET /api/v1/capabilities/{id}/usage-stats`, `POST /api/v1/capabilities/usage-stats` | `agent_count`, `agent_names` | `sensor_count`, `sensor_names` |
| `GET /api/v1/platform/stats` → `tier_stats.<tier>` | `total_agents`, `online_agents`, `offline_agents` | `total_sensors`, `online_sensors`, `offline_sensors` |
| Tenable integration `config` (`POST/PUT /api/v1/integrations`, integration responses) | `execution_mode: "agent"`, key `agent_id` | `execution_mode: "sensor"`, key `sensor_id`; the API now rejects `"agent"` (`invalid execution_mode … (want sensor\|direct)`) |

Value changes in management responses:

| Field | Before | After |
|---|---|---|
| asset `source_type` | `agent` | `sensor` |
| asset / asset service `discovery_source` | `agent` | `sensor` |
| asset state history `source` | `agent` | `sensor` (historical rows are stored as `agent` and returned as `sensor`; a `source=sensor` filter matches both) |
| tenant module id | `agents` | `sensors` (module catalog, tenant module toggles, `/me` modules) |
| notification event types | `agent.offline`, `agent.error` (category `agents`) | `sensor.offline`, `sensor.error` (category `sensors`) |

## 4. Permissions

Renamed in place by migration 000230 in the catalog, every system and custom
role, every group grant, every permission set and every `oct_` API-key scope.
Effective access is unchanged (verified by `TestSensorRenameUpgrade`).

| Before | After |
|---|---|
| `agents:read` | `sensors:read` |
| `agents:write` | `sensors:write` |
| `agents:delete` | `sensors:delete` |
| `agents:commands:read` | `sensors:commands:read` |
| `agents:commands:write` | `sensors:commands:write` |
| `agents:commands:delete` | `sensors:commands:delete` |

Permission ids are re-resolved from the database on every request, so a
logged-in user keeps access; the per-user permission cache (Redis, 5-minute
TTL) can hold the old ids for up to five minutes after the migration, during
which a non-admin member may be refused a sensors route. Owners and admins
are unaffected.

Platform admin console (RFC-022) action ids, enforced in code only:
`agent:create|update|delete|disable|enable|list|get|stats` →
`sensor:create|update|delete|disable|enable|list|get|stats`.

Sensor API-key scopes (stored on `sensor_api_keys`, not shown in the UI):
`agent:heartbeat` → `sensor:heartbeat`, `agent:read` → `sensor:read`,
`agent:write` → `sensor:write`, `admin:agents` → `admin:sensors`.

## 5. Audit action ids

New events use the new ids. Rows written before the upgrade keep the old ids
(the audit log is hash-chained; rewriting it would break verification).
A filter on a `sensor.*` action or on resource type `sensor` also returns the
historical rows; the API returns each row as written, so **the UI must label
both spellings**.

| Before (historical rows) | New events |
|---|---|
| `agent.created` | `sensor.created` |
| `agent.updated` | `sensor.updated` |
| `agent.deleted` | `sensor.deleted` |
| `agent.activated` | `sensor.activated` |
| `agent.deactivated` | `sensor.deactivated` |
| `agent.revoked` | `sensor.revoked` |
| `agent.key_regenerated` | `sensor.key_regenerated` |
| `agent.key_renewed` | `sensor.key_renewed` |
| `agent.connected` | `sensor.connected` |
| `agent.disconnected` | `sensor.disconnected` |
| resource type `agent` | resource type `sensor` |
| metadata `agent_type` (sensor.created) | `sensor_type` |
| metadata `agent_id`, `agent_name` (ingest.* events) | `sensor_id`, `sensor_name` |
| message `Agent '<name>' …` | `Sensor '<name>' …` |

Platform admin audit log (`admin_audit_logs`, not chained, kept as written):
`agent.create|update|delete|enable|disable` → `sensor.create|update|delete|enable|disable`,
resource type `agent` → `sensor`.

## 6. Error codes and messages

| Where | Before | After |
|---|---|---|
| `POST /api/v1/scans/{id}/trigger`, `POST /api/v1/scans/quick` | code `NO_AGENT_AVAILABLE` | `NO_SENSOR_AVAILABLE` |
| Management 404 / 409 | `Agent not found`, `Agent already exists` | `Sensor not found`, `Sensor already exists` |
| Other management messages | "agent" in prose (e.g. `No tenant agent available. Deploy an agent to execute scans.`) | "sensor" (`No tenant sensor available. Deploy a sensor to execute scans.`) |

Messages are prose; no client should match on them. Codes other than the one
above did not change.

## 7. Outbound contracts (logs, metrics, environment)

| Kind | Before | After |
|---|---|---|
| Log field | `agent_id`, `agent_name` | `sensor_id`, `sensor_name` |
| Logger names | `handler=agent`, `service=agent`, `service=agent_selector` | `handler=sensor`, `service=sensor`, `service=sensor_selector` |
| Background job names | `agent-health`, `agent-health-checker` | `sensor-health`, `sensor-health-checker` |
| Security event names | `security.agent.not_found`, `security.agent.inactive`, `security.agent.type_mismatch` | `security.sensor.not_found`, `security.sensor.inactive`, `security.sensor.type_mismatch` |
| Metrics | `agents_online`, `agent_commands_executed_total{agent_id}`, `agent_heartbeat_latency_seconds`, `platform_agents_active` | `sensors_online`, `sensor_commands_executed_total{sensor_id}`, `sensor_heartbeat_latency_seconds`, `platform_sensors_active` |
| New metric | — | `deprecated_management_path_requests_total{method}` |
| Redis keys (internal, TTL-bound) | `agent:heartbeat:*`, `agent:status:*`, `agent:jobs:*`, `agent:config:*`, `agent:prev_health:*`, `platform:agents:online`, `platform:agent:status:*` | same with `sensor` |

The four renamed sensor metrics are registered but were never incremented, so
no existing dashboard series is lost. Webhook, notification and report/CSV
payloads carry no agent-named fields; the notification event types above are
the only outbound ids, and nothing emits them today.

API server environment variables (`AGENT_*` → `SENSOR_*`). The old names keep
working: the new name is read first, the old one is applied with a startup
`WARN deprecated configuration` line naming both, and startup fails only when
both are set to different values.

| Before | After |
|---|---|
| `AGENT_CONFIG_TEMPLATES_DIR` | `SENSOR_CONFIG_TEMPLATES_DIR` |
| `AGENT_PUBLIC_API_URL` | `SENSOR_PUBLIC_API_URL` |
| `AGENT_KEY_TTL` | `SENSOR_KEY_TTL` |
| `AGENT_LB_JOB_WEIGHT` | `SENSOR_LB_JOB_WEIGHT` |
| `AGENT_LB_CPU_WEIGHT` | `SENSOR_LB_CPU_WEIGHT` |
| `AGENT_LB_MEMORY_WEIGHT` | `SENSOR_LB_MEMORY_WEIGHT` |
| `AGENT_LB_DISK_IO_WEIGHT` | `SENSOR_LB_DISK_IO_WEIGHT` |
| `AGENT_LB_NETWORK_WEIGHT` | `SENSOR_LB_NETWORK_WEIGHT` |
| `AGENT_LB_MAX_DISK_THROUGHPUT_MBPS` | `SENSOR_LB_MAX_DISK_THROUGHPUT_MBPS` |
| `AGENT_LB_MAX_NETWORK_THROUGHPUT_MBPS` | `SENSOR_LB_MAX_NETWORK_THROUGHPUT_MBPS` |

The default template directory moved from `configs/agent-templates` to
`configs/sensor-templates`; when only the old directory exists (for example a
mounted configmap) it is used, with a warning.

## 8. Stored values migration 000230 converts

| Data | Conversion |
|---|---|
| Tables | `agents` → `sensors`, `agent_api_keys` → `sensor_api_keys` |
| Columns | `agent_id` → `sensor_id` in `sensor_api_keys`, `commands`, `findings`, `ingest_jobs`, `pipeline_runs`, `runtime_telemetry_events`, `scan_sessions`, `step_runs`, `tool_executions`; `commands.platform_agent_id` → `platform_sensor_id`; `scans.agent_preference` → `sensor_preference`; `sensors.is_platform_agent` → `is_platform_sensor` |
| Constraints (16), indexes (28), trigger, RLS policy | renamed (`agents_*`/`*_agent_*` → `sensors_*`/`*_sensor_*`) |
| Functions | `get_next_platform_job(p_sensor_id, …)`, `recover_stuck_platform_jobs`, `recover_stuck_tenant_commands` rewritten |
| Permission catalog and grants | `agents:*` → `sensors:*` in `permissions`, `role_permissions`, `group_permissions`, `permission_set_items`, `api_keys.scopes` |
| Module | `modules` row `agents` → `sensors` (and `permissions.module_id`, `event_types.module_id`, `asset_types.module_id`, `modules.parent_module_id`, `tenant_modules.module_id`); descriptions of `commands` and `scans` |
| Notification event types | `event_types` `agent.offline`/`agent.error` → `sensor.*` (category `sensors`); references in `webhooks.event_types`, `integration_notification_extensions.enabled_event_types`, `notification_preferences.muted_types` |
| Sensor API-key scopes | `sensor_api_keys.scopes`: `agent:heartbeat|read|write`, `admin:agents` → `sensor:*`, `admin:sensors` |
| Pipeline templates | `settings.agent_preference` → `settings.sensor_preference` |
| Tenable integrations | `config.execution_mode` `agent` → `sensor`; `config.agent_id` → `config.sensor_id` |
| Assets | `source_type` and `discovery_source` `agent` → `sensor`; `asset_services.discovery_source` likewise (`updated_at` left untouched) |
| Catalog comments | updated |

Deliberately kept, with the reason:

| Data | Why |
|---|---|
| `audit_logs` rows `agent.*` / resource type `agent` | hash-chained history; reads treat both as one family |
| `admin_audit_logs`, `notification_events` | history (`webhook_deliveries` was empty and was dropped by 001056) |
| `asset_state_history.source = 'agent'` | the table is append-only (a trigger rejects UPDATE); returned as `sensor` |
| `commands.payload.agent_preference` | protocol v1 job content |
| `sensors.type` values | legacy v1 type values (RFC-023 §9.1 adds role + deployment later) |
| `user_agent`, `actor_agent` columns | the HTTP User-Agent |
| `deprecated.*` schema | frozen archive; dropped by 001056 (every table was empty) |
| tenant AI mode `agent`, module `ai_triage.agent` | an LLM agent, not a sensor |

## 9. Compatibility views

**None.** Views can stand in for the two renamed tables, but not for the
columns renamed inside shared tables (`commands`, `findings`, `scan_sessions`,
…): an old binary would still fail on those, so views would only hide part of
the breakage. The upgrade is therefore stop-old → migrate → start-new (the
default single-replica compose and Helm deployments already run migrations
before the new API starts). Running an old and a new API binary against the
same database at once is not supported for this release.

## 10. Upgrade check

```bash
# compose / container
docker compose exec api ./server -sensor-upgrade-check
# or with the binary and the API's environment
./server -sensor-upgrade-check
```

Prints one line per probe (`ok`, `kept`, `LEFTOVER`) and exits 0 when nothing
migration 000230 should have converted is left, 1 otherwise. A cheap subset
runs at every API start and logs `WARN pre-sensor vocabulary left after
upgrade` per leftover.

## 11. UI follow-up checklist

- Call `/api/v1/sensors/*`; rename the `agents` query keys and API hooks.
- Permission constants `agents:*` → `sensors:*` (sidebar, route permissions,
  role editor labels, dev-auth fixtures).
- Module id `agents` → `sensors` (`use-tenant-permissions`, module toggles).
- Field names in section 3, including `sensor` in the create response, the
  `X-Sensor-API-Key` header and the `sensor_id` command filter.
- Tenable integration form: `execution_mode` `sensor`, `sensor_id`.
- Audit log page: label both `agent.*` and `sensor.*`, resource types `agent`
  and `sensor`, metadata `agent_*` and `sensor_*`.
- Notification preferences: event types `sensor.offline` / `sensor.error`.
- `NO_SENSOR_AVAILABLE` if the code is matched anywhere.
- Redirect `/agents` UI routes to `/sensors`; migrate localStorage keys that
  embed `agent`.
