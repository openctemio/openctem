# Tool availability

**Question it answers:** which tools can this organization scan with right
now, on which sensors, and at which versions?

The catalog (`tools`) lists the tools the platform knows. It does not say whether
any sensor of the organization has a tool. That information comes from the
sensors themselves: each sensor registers a manifest
([RFC-033](../rfcs/RFC-033-sensor-manifest.md)) listing its tools, their
versions and their content (for example nuclei templates). The platform keeps the
sanitized tools of the current manifest on the sensor row (`sensors.reported_tools`,
`reported_tool_names`, `reported_at`).

The availability view joins the two, per tenant.

## The tool resource

Tools are one resource, `/api/v1/tools`: the organization's view of the
catalog, platform tools plus its own custom tools (another tenant's custom
tools never appear).

| Route | Permission | What |
|---|---|---|
| `GET /tools` | `scans:tools:read` | Filters `source=platform\|custom`, `category`, `q`, `enabled`, `available`, `zone_id`; `sort=name\|created_at\|updated_at` (`-` descending); `page`, `per_page` (max 100, 50 with availability or stats). |
| `GET /tools/{id}` | `scans:tools:read` | A platform tool or the tenant's own custom tool; any other id is 404. |
| `PATCH /tools/{id}/settings` | `scans:tenant_tools:write`; with `config`, also `scans:tools:write` | The tenant's switch and config overrides; an omitted field is left as it is, `"config": {}` clears the overrides. Overrides change what the sensors run, hence the admin-level permission. A config with a secret-shaped key or value is refused: credentials live in the secret store, referenced by id. |
| `PATCH /tools/settings` | `scans:tenant_tools:write` | `{"tool_ids": [...], "is_enabled": bool}`; ids the tenant cannot see are ignored. |
| `POST /tools` | `scans:tools:write` | Creates a custom tool of the tenant (the tenant comes from the token). |
| `PUT`/`DELETE /tools/{id}` | `scans:tools:write` / `scans:tools:delete` | The tenant's own custom tools only; a platform tool or another tenant's is 404 (the service reads the tool by tenant and id). |
| `GET /tool-categories[?source=]`, `GET /tool-categories/{id}` | `scans:tools:read` | Platform categories plus the tenant's own. |
| `POST`/`PUT`/`DELETE /tool-categories[/{id}]` | `scans:tools:write` / `scans:tools:delete` | The tenant's own custom categories only (others 404). |

Platform tools are managed by the platform (migrations and the seed). No
tenant route changes them; there is no platform-admin tool route either.

### include=

`include=settings,availability,stats` adds the tenant's data to each tool. The
shared package `internal/infra/http/include` applies one model to every
resource that offers includes; each resource
runs its conformance suite (`include/includetest.RunConformance`) from its
DB-backed route test:

- a whitelist per resource; an unknown value, a nested one (`settings.config`)
  or more than 3 values is refused with `400 INVALID_INCLUDE` before any read;
- each include needs the permission of its former standalone route
  (`scans:tenant_tools:read`; `stats` also `scans:read`, as the counts are
  tenant-wide over every scan, not limited to a data scope); one the caller
  lacks is left out and named in `meta.omitted_includes` (no 403, so no
  oracle); include names that would expose secrets, credentials, audit
  internals or personal data cannot be registered;
- each include is loaded once for the whole page (one availability
  computation, one statistics query), never per row; `availability` and
  `stats` are expensive: `per_page` is capped at 50 and each costs 2 more
  read-limiter tokens;
- the projection is an explicit response type: `settings` never takes a
  secret (refused at write; older rows masked); `availability.sensors`
  (names, zones) needs `sensors:read`, otherwise only the counts are given;
- a response that took `include=` is `Cache-Control: private, no-store`, and
  nothing is cached server-side;
- the included objects are optional in the OpenAPI and web types; the web
  treats an absent one as unknown, never as a default.

The `enabled` and `available` filters read the same data and need
`scans:tenant_tools:read` (403 without it: a filter cannot be left out).

## Availability

`GET /api/v1/tools?include=availability[&zone_id=<scan zone>]`.

Every catalog tool the tenant sees (platform tools plus its own custom tools,
active or not) is listed. So is every tool one of its sensors reports that the
catalog does not list (`in_catalog: false`, never enabled). For each tool the
response gives (per tool in `availability`; the tools only the sensors report
are in `availability.unlisted`):

| Field | Meaning |
|---|---|
| `enabled` | Active in the catalog and switched on for the tenant (`tenant_tool_configs.is_enabled`). |
| `status` | Derived (see below). |
| `sensors_online` / `sensors_total` | Sensors that may run the tool, and how many of them take work now. |
| `sensors_excluded` | Sensors that have the tool but may not run it (see "Exclusions"). |
| `sensors[]` | Each sensor reporting the tool: id, name, state, online, zones, version, content, exclusion. Listed only to callers holding `sensors:read`. The counts are given to everyone. |
| `versions`, `min_reported_version`, `max_reported_version` | Distinct versions the runnable sensors report, oldest first. |
| `content[]` | Per content name, the versions the sensors report. |
| `min_version` | The oldest version the catalog accepts (`tools.min_version`, migration 001153). Custom tools set it through the custom tool API. |
| `latest_version` | The newest version known: the catalog's `latest_version`, or the newest reported version if that is newer. |
| `update_available` | A runnable sensor reports a version below `latest_version`. |
| `last_reported_at` | The newest manifest among the sensors listed. |

`availability.summary` counts every tool per status (filters not applied).
`zone_id` limits the view to the sensors assigned to that scan zone. A zone of
another tenant answers 404.

### Status

| Status | When |
|---|---|
| `disabled` | The tenant (or the catalog) switched the tool off. |
| `no_sensor` | Enabled, but no sensor that may run it reports it. |
| `offline_only` | Sensors report it, but none takes work now. |
| `outdated` | On online sensors, but every one of them reports a version below `min_version`. A sensor that reports no version is never counted as outdated. |
| `ready` | Enabled, and at least one online sensor runs it at an accepted version. |

`ready` and `outdated` are *runnable*: a scan job for the tool can be dispatched
now. The `available=true` filter on `GET /api/v1/tools` is the same answer.

### Online

"Online" is the Sensors page's definition, in one place:
`sensor.State.TakesJobs()` (online, degraded or late) and not a one-shot (CI)
sensor (`Sensor.CanTakeJobs`). The fleet stats use the same function.

### Exclusions

A sensor that reports a tool installed may still be unable to run it. The view
asks the same rules admission applies to a scan job for that tool. An administrator narrows a sensor's tools through its grant.

- `grant`: the sensor's grant ([RFC-052](../rfcs/RFC-052-sensor-pairing-and-authorization.md)) refuses the job (`Grant.Admit`). This covers job types, tools, and the tool's tier above the ceiling. A New sensor runs passive tools only.
- `local_policy`: the sensor's own local policy refuses the job (`sensor.Accepts`). This covers the policy's tool or job list and the kill switch.

Excluded sensors are listed with the reason. They count in `sensors_excluded`,
not in `sensors_total`.

## Trigger-time refusal

A trigger (manual, scheduled, or a quick scan) is refused with
`NO_SENSOR_FOR_TOOL` (400) when a tool it needs has no online sensor that may
run it. The tool is the scan's scanner, or the tool of each workflow step
(including tools resolved from a step's capabilities). This replaces queueing
jobs that nobody claims and that sit pending until they expire. A scan pinned
to a scan zone is judged on that zone's sensors only. Automatic routing still
refuses a zone without a sensor for the tool with `NO_ZONE_COVERAGE` when it
plans the batches.

The error body carries `details`:
`{tool, step, status, sensors_total, sensors_online, sensors_excluded, zone_id}`.
Its message says what to do: no sensor has the tool, none of them is online,
or they have it but may not run it.

Some cases are left to the checks that already own them:

- A disabled tool keeps `TOOL_DISABLED`.
- A connector scan runs through its integration, so it is not checked here.
- When availability cannot be read, the trigger continues to the existing
  sensor availability check (`NO_SENSOR_AVAILABLE`).

The trigger codes `NO_SENSOR_FOR_TOOL`, `NO_SENSOR_AVAILABLE`, `TOOL_NOT_FOUND`,
`TOOL_DISABLED` and `TOOL_NOT_SCANNER` now reach the client in the error body's
`code`. They used to be reported as `BAD_REQUEST`.

## Web console

Every screen that shows or picks a tool reads this one endpoint, through `useToolAvailability`
(`web/src/lib/api/tool-hooks.ts`). The helpers live in `web/src/features/tools/lib/availability.ts`:
status labels, `isRunnable` and `toolUnavailableReason`. The shared pieces are in
`web/src/features/tools/components/tool-availability.tsx`: the status pill, the "n/m online" cell
with its sensor popover, and the sensor list.

- **Settings > Scanning > Tools**
  - **Columns:** Tool, Category, Status (with a tooltip), Sensors (n/m online, with a popover listing each sensor, its zone, version and exclusion), Version(s) (with an update badge), Last reported, Enabled.
  - **Default filter:** the tools at least one sensor reports. "Show full catalog" adds the rest.
  - **Metrics:** Ready, Offline only, No sensor, Outdated, Disabled and Updates available. Each one filters the table.
  - **Enabled switch:** the organization's own on/off per tool (`PATCH /api/v1/tools/settings`).
  - **Tool detail:**
    - an "On your sensors" section with sensors, versions, content and last report;
    - the install details, under "How to add this tool to a sensor";
    - a callout with the reason when a scan cannot run.
- **Scan builder** (New/Edit scan, Quick scan): a scanner no online sensor may run is listed, disabled, with the reason. Availability is judged in the scan's zone when one is selected. A scan's current scanner stays selectable, with a warning.
- **Workflow builder:** the node palette and the step tool picker grey out such tools with the same reason.
- **Sensor detail:** the tool list marks an installed tool the grant or local policy refuses.
- **Capabilities page:** the tool tooltip says which of a capability's tools are ready on your sensors.

## Trust and isolation

- **Display and advice only.** What a sensor reports is a claim. The claim-time
  gates stay authoritative for every job: dispatch tools, zone predicate, grant
  and local policy.
- **Tenant-scoped reads.** The view reads only the caller's own sensors (shared
  platform sensors are left out, as on the Sensors page), their grants and zones,
  and the catalog the tenant may see. A defensive check drops any sensor of
  another tenant that a lister returned. `tool_availability_db_test.go` covers
  another tenant's sensors, custom tools and zones.
- **Least privilege.** Sensor names and zones are listed only to holders of
  `sensors:read`. The scan builder needs only the counts.
- **Fail-open for pickers.** If availability cannot be read, `is_available` is
  `true`, so a picker is never blocked by an outage. Trigger time still refuses
  work no sensor can run.

## Code

| Layer | Where |
|---|---|
| Domain | `pkg/domain/sensor/tool_availability.go` (`ComputeToolAvailability`, statuses, exclusions), `fleet_health.go` (`TakesJobs`, `CanTakeJobs`), `version.go` (`CompareVersions`) |
| App | `internal/app/tool/availability.go` (`ToolAvailability`, `ToolAvailabilityFor`, `RunnableToolNames`), `internal/app/scan/tool_availability_gate.go` (trigger refusal) |
| Infra | `SensorGrantRepository.ListByTenant`, `ScanZoneRepository.List`, `SensorService.ListAllSensors` |
| HTTP | `internal/infra/http/handler/tool_availability_handler.go` |
