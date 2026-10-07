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

## Endpoint

`GET /api/v1/tenant-tools/availability[?zone_id=<scan zone>]`, gated by
`scans:tenant_tools:read`.

Every catalog tool the tenant sees (platform tools plus its own custom tools,
active or not) is listed. So is every tool one of its sensors reports that the
catalog does not list (`in_catalog: false`, never enabled). For each tool the
response gives:

| Field | Meaning |
|---|---|
| `enabled` | Active in the catalog and switched on for the tenant (`tenant_tool_configs.is_enabled`). |
| `status` | Derived (see below). |
| `sensors_online` / `sensors_total` | Sensors that may run the tool, and how many of them take work now. |
| `sensors_excluded` | Sensors that have the tool but may not run it (see "Exclusions"). |
| `sensors[]` | Each sensor reporting the tool: id, name, state, online, zones, version, content, exclusion. Listed only to callers holding `sensors:read`. The counts are given to everyone. |
| `versions`, `min_reported_version`, `max_reported_version` | Distinct versions the runnable sensors report, oldest first. |
| `content[]` | Per content name, the versions the sensors report. |
| `min_version` | The oldest version the catalog accepts (`tools.min_version`, migration 001149). Custom tools set it through the custom tool API. |
| `latest_version` | The newest version known: the catalog's `latest_version`, or the newest reported version if that is newer. |
| `update_available` | A runnable sensor reports a version below `latest_version`. |
| `last_reported_at` | The newest manifest among the sensors listed. |

`summary` counts the tools per status. `zone_id` limits the view to the sensors
assigned to that scan zone. A zone of another tenant answers 404.

### Status

| Status | When |
|---|---|
| `disabled` | The tenant (or the catalog) switched the tool off. |
| `no_sensor` | Enabled, but no sensor that may run it reports it. |
| `offline_only` | Sensors report it, but none takes work now. |
| `outdated` | On online sensors, but every one of them reports a version below `min_version`. A sensor that reports no version is never counted as outdated. |
| `ready` | Enabled, and at least one online sensor runs it at an accepted version. |

`ready` and `outdated` are *runnable*: a scan job for the tool can be dispatched
now. The `is_available` flag on `GET /api/v1/tenant-tools/all-tools` and
`/{toolId}/with-config` is the same answer.

### Online

"Online" is the Sensors page's definition, in one place:
`sensor.State.TakesJobs()` (online, degraded or late) and not a one-shot (CI)
sensor (`Sensor.CanTakeJobs`). The fleet stats use the same function.

### Exclusions

A sensor that reports a tool installed may still be unable to run it. The view
asks the same rules dispatch applies to a scan job for that tool:

- `sensor_settings`: the administrator's tool list on the sensor leaves the tool out (`effective_tools`).
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
