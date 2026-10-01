# Scan zones

> RFC: [RFC-023](../rfcs/RFC-023-scan-zones-and-scanners.md) Phase 1 (D3–D7
> layers 1–2, D14, D16, §5, §6, §11, §12). Vocabulary: [sensors.md](sensors.md).

A **scan zone** is a tenant-owned set of address ranges plus the sensors that
may scan them. Zones answer "who can reach this address"; scope answers "may we
scan it" (D17). Zones are opt-in: a tenant without zones dispatches exactly as
before.

## Data model (migration 000231)

| Table / column | Purpose |
|---|---|
| `scan_zones` | `tenant_id`, `name` (unique per tenant, case-insensitive), `description`, `is_default` (at most one per tenant), `ranges cidr[]`, `created_by`, timestamps. Only the default zone may have no ranges. |
| `scan_zone_sensors` | `(tenant_id, zone_id, sensor_id)`. Composite foreign keys to `scan_zones (tenant_id, id)` and `sensors (tenant_id, id)`: a zone and a sensor of different tenants cannot be linked, whatever the caller does. The insert additionally refuses platform sensors. |
| `commands.scan_zone_id` | The zone a command was routed to. No foreign key on purpose: a dangling id keeps the claim predicate failing closed. A zone with pending/acknowledged/running commands cannot be deleted (409). |
| `sensors` constraint `uq_sensors_tenant_id_id` | Target of the composite key. |

`scan_networks` (RFC §5, D15) is Phase 4 and not created: nothing in Phase 1
reads a network.

### Range validation (RFC §11)

`pkg/domain/scanzone.ParseRanges` accepts an address, a CIDR (host bits are
masked) or an inclusive range `a-b` (expanded to at most 16 CIDRs). IPv4-mapped
IPv6 becomes IPv4. The list is sorted, deduplicated and contained prefixes are
dropped. Rejected:

- anything overlapping the deny list: `0.0.0.0/8`, `127.0.0.0/8`,
  `169.254.0.0/16` (IMDS), `224.0.0.0/4`, `240.0.0.0/4`, `::/128`, `::1/128`,
  `fe80::/10`, `ff00::/8` (so `0.0.0.0/0` and `::/0` are rejected too);
- IPv4 wider than `/8`, IPv6 wider than `/32`;
- more than 256 prefixes per zone; more than 500 zones per tenant.

## Routing at trigger time (layer 1)

`internal/app/scan/zones.go`, called from `trigger.go` after targets are
materialised (direct targets + asset-group members, scope exclusions removed,
failing closed, as in api#555).

1. Load the tenant's zones. None → the pre-zone path, unchanged. Lookup error →
   the trigger fails (no zones known, no safe dispatch).
2. Tools whose `supported_targets` are only `file`/`repository`/`container`
   (SAST, SCA, secrets, IaC) are not network scans and are not routed (D20).
3. `scanzone.Router` assigns each target:
   - address or CIDR → the zone with the **narrowest** range holding all of it
     (ties: zone name, then id);
   - hostname → resolved from the platform (`net.DefaultResolver`, 3 s per
     lookup, 8 concurrent); the narrowest zone holding any resolved address;
   - public and in no range → the **default zone**; with no default zone it is
     *unzoned* and dispatched as before zones (any tenant sensor);
   - private (RFC 1918, CGNAT, ULA) and in no range, a CIDR only partly inside
     a zone, an address in the deny list, a hostname resolving to such an
     address, or a hostname that does not resolve → **uncovered**.
4. Targets of a zone are batched: `targets_per_job` per command for scanners
   that read a target list (nuclei, tenable, nessus), one per command for every
   other scanner. At most 1000 commands per run.
5. Each batch is pinned to the **least busy** healthy sensor of its zone that
   has the scan's tool (fewest pending/acknowledged/running commands pinned to
   it, then `current_jobs / max_concurrent_jobs`, then name), balancing within
   the run. Healthy = `status='active'`, `health='online'`, has heartbeated, key
   not expired, pulls jobs (daemon/worker). Phase 2 adds approval state.
6. A zone whose sensors are all unhealthy gets its batches **unpinned but
   stamped** with the zone: they wait for a zone sensor (warning on the run). A
   zone with no sensors assigned makes its targets uncovered.
7. Zone batches are never platform jobs (D14). Unzoned public batches keep the
   pre-zone platform/tenant rules.
8. Every uncovered target is listed in the run's `dispatch_warnings` (with its
   reason) and `uncovered_targets`; `zone_routing` summarises the routing. If no
   target is left, the trigger fails with `NO_ZONE_COVERAGE`.

Each batch payload carries only its own targets: `targets`/`target`, a
`scanner_config` whose `targets`/`target` keys are rewritten to the batch
(quick scans store their list there), and a run context without the run-wide
`targets`, `scanner_config`, warnings or routing report. The protocol-v1 wire
shape is unchanged.

**Workflow scans** run as one pipeline, so their routed targets must fall in a
single zone (or all be unzoned): otherwise the trigger fails with
`ZONE_SPLIT_REQUIRED`. The run is stamped with the zone (`scan_zone_id` in the
run context) and every step command, including those the pipeline service
schedules later, is stamped with it and left to the zone's sensors.

### Run completion with batches

All batch commands of a single scan share the run's one step run
(`commands.step_run_id`). `pipeline.Service.OnStepCompleted/OnStepFailed` ask
the command repository (`command.StepBatchGate`) for the batches of the step:
while one is still active nothing is recorded; when the last one finishes, the
caller that wins `UPDATE step_runs SET completed_at = NOW() WHERE completed_at
IS NULL` records the outcome once: completed with the summed `findings_count`,
or failed ("k of n scan batches failed: <first error>", no generic retry, since
that would re-dispatch without zone routing). A step with one command keeps the
original behaviour.

## Claim predicate (layer 2)

`GetPendingForSensor` (poll) and `ClaimForSensor` (acknowledge) share
`zoneClaimPredicate`: a command with `scan_zone_id` is offered only to a sensor
assigned to that zone, in the same tenant, that has the command's tool
(`payload.scanner`, or `payload.preferred_tool` for workflow steps). This holds
for pinned commands too, and after the reaper (`recover_stuck_tenant_commands`)
unpins a stuck command, so a re-queued zone job can only move to another sensor
of the same zone. Unassigning a sensor unpins its pending commands of that zone.
Commands without a zone keep the pre-zone rule (pinned to me, or unpinned).

## Scan creation (D6)

Private targets are refused at creation unless a zone of the tenant covers
them; then they are accepted and later scanned only through that zone. Loopback,
link-local and every other deny-list address stay refused. Tenants without
zones keep refusing all private targets.

## Results

Ingest (protocol v1) does not carry the command that produced a report, so
findings and assets are not stamped with a zone yet; the zone is recorded on the
command (`commands.scan_zone_id`). Per-record provenance (sensor, zone) is
Phase 2 (D21).

## Coverage view (V3)

`GET /api/v1/scan-zones/coverage` counts the tenant's inventory addresses
(assets of type `ip_address`, `host`, `server` whose name is one IP address):
inside a zone range, public outside every range, private outside every range
(scans skip these). Per zone: assigned and healthy sensors, addresses inside.
Warnings: `no_sensors_assigned`, `private_ranges_without_healthy_sensor`,
`default_zone_without_healthy_sensor`, `private_addresses_outside_zones`,
`public_addresses_without_default_zone`.

## Audit

`scan_zone.created`, `scan_zone.updated` (with changes), `scan_zone.deleted`,
`scan_zone.sensor_assigned`, `scan_zone.sensor_unassigned`; resource type
`scan_zone`.

## Known limits (Phase 1)

- No zone picker on a scan yet: routing is automatic.
- Hostnames are resolved once, at trigger time, from the platform's DNS; the
  sensor resolves again when it scans (pinning is layer 3, Phase 3).
- A range spanning two zones is not split; it is reported uncovered.
- Routing covers `scan/trigger.go`. The Tenable coverage dispatcher and
  validation jobs do not use zones yet.
- A zone deleted while a trigger is creating its commands leaves those commands
  unclaimable (fail closed); they expire.

## UI contract

For the Scan zones tab (Settings → Sensors) and the New-scan screen. All routes
use the JWT tenant; errors use the standard `apierror` body
(`{"code","message"}`).

| Method and path | Permission | Request | Response |
|---|---|---|---|
| `GET /api/v1/scan-zones` | `sensors:zones:read` | — | `{"data": [Zone], "total": n}` |
| `GET /api/v1/scan-zones/coverage` | `sensors:zones:read` | — | `Coverage` |
| `GET /api/v1/scan-zones/{id}` | `sensors:zones:read` | — | `Zone` |
| `POST /api/v1/scan-zones` | `sensors:zones:write` | `{"name", "description"?, "is_default"?, "ranges": [string]}` | `201 Zone` |
| `PATCH /api/v1/scan-zones/{id}` | `sensors:zones:write` | any of `name`, `description`, `is_default`, `ranges` | `Zone` |
| `PUT /api/v1/scan-zones/{id}/sensors/{sensorId}` | `sensors:zones:write` | — | `Zone` (idempotent) |
| `DELETE /api/v1/scan-zones/{id}/sensors/{sensorId}` | `sensors:zones:write` | — | `204` |
| `DELETE /api/v1/scan-zones/{id}` | `sensors:zones:delete` | — | `204` |

```
Zone = {
  "id", "tenant_id", "name", "description", "is_default": bool,
  "ranges": ["10.230.0.0/16", "fd00:230::/48"],   // normalised
  "sensor_ids": ["<uuid>"], "created_by"?, "created_at", "updated_at"
}
Coverage = {
  "inventory_addresses", "in_zones", "outside_public", "outside_private": int,
  "has_default_zone": bool,
  "zones": [{"zone_id", "name", "is_default", "has_private_range",
             "assigned_sensors", "healthy_sensors", "addresses"}],
  "warnings": [{"code", "zone_id"?, "message"}]
}
```

Status codes to handle: `400` invalid range or name (message says which range
and why), `404` zone or sensor not in this tenant, `409` duplicate name
(`ZONE_NAME_TAKEN`), second default zone (`DEFAULT_ZONE_EXISTS`), or deleting a
zone with queued/running jobs (`ZONE_IN_USE`).

Scan runs: `GET /api/v1/pipeline-runs/{id}` now returns a `dispatch` object
when the trigger recorded one:

```
"dispatch": {
  "resolved_targets": 5, "excluded_targets": 1,
  "warnings": ["db01.corp.example not scanned: hostname did not resolve ..."],
  "uncovered_targets": [{"target", "reason"}],          // first 100
  "zone_routing": {
    "jobs", "targets_per_job", "unzoned_targets", "uncovered_targets",
    "zone_id"?,                                          // workflow runs
    "zones": [{"zone_id", "zone_name", "targets", "jobs", "queued_jobs", "sensor_ids"}]
  },
  "sensor_routing": "tenant" | "platform"               // single-scanner runs
}
```

`resolved_targets` counts the direct targets plus the members of **every**
asset group of the scan (`asset_group_ids`), deduplicated, after scope
exclusions; the 10,000-target cap applies to all groups together. An empty
group is named in `warnings`.

`sensor_routing` is decided once, before the run is created. Nothing falls
back silently (D14): `sensor_preference: platform` with an asset group, an
internal target, a zoned target, or a tenant without platform access refuses
the trigger (`PLATFORM_SENSOR_REFUSED`). In `auto` mode a failed sensor lookup
keeps the job on tenant sensors and adds a warning.

Trigger errors the New-scan screen should explain: `NO_ZONE_COVERAGE`,
`ZONE_SPLIT_REQUIRED`, `TOO_MANY_JOBS`, `NO_TARGETS` (the scan resolves to no
target: empty asset groups and no direct targets), `ALL_TARGETS_EXCLUDED`,
`PLATFORM_SENSOR_REFUSED` (all `400`). No run or command is created. Scan creation with a private
target outside every zone fails with `400` naming the target.

UI permission constants to add: `sensors:zones:read`, `sensors:zones:write`,
`sensors:zones:delete`. Audit-log labels: the five `scan_zone.*` actions and
resource type `scan_zone`.
