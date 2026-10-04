# Tenable.sc sensor connector

Design: [RFC-047](../rfcs/RFC-047-tenable-sc-sensor-connector.md). This page
describes what is built and where it lives.

## Switch

Everything here is behind `integration.TenableConnectorEnabled` (owner
decision D-14; `TENABLE_CONNECTOR_ENABLED` in the web). While it is false,
Tenable integrations cannot be created (the connector validator is not
wired), the sync and coverage controllers are not registered, and the page
stays hidden. Flip it when a sensor release with the connector
(openctemio/sensor#129, #131) is out.

## Shape

```
integration (provider tenable, engine tenable_sc, execution_mode sensor,
             sensor_id, instance, min_severity, full_sync_days, repositories)
   │  "Sync now" (POST /api/v1/integrations/{id}/sync, integrations:manage)
   │  or the tenable-sc-sync controller (every 2 min; due by sync_interval_minutes)
   ▼
tenablesc.Service.RequestSync ── connector_sync command, pinned to sensor_id
   │                              (payload: scanner=tenable_sc, instance, mode,
   │                               window_days, include, min_severity, repositories)
   ▼
sensor (openctemio/sensor internal/connector/tenablesc; keys and URL only there)
   │  Tenable.sc /rest/analysis, /rest/plugin, /rest/status
   ▼
CTIS reports, tool tenable_sc, coverage incremental, bound to the command
   ▼
ingest: RFC-043 network VA identity; mitigated rows → source-asserted resolve
   ▼
tenablesc.Service.Reconcile: command completed + its v2 reports completed →
integration metadata.tenable_sync (cursor, counts, license), status connected
```

## Platform pieces

| Piece | Where |
|---|---|
| Connector config, sync request, cursor, reconcile, schedule | `internal/app/tenablesc/` |
| Schedule controller | `internal/infra/controller/tenable_sc_sync.go` |
| Scheduled-sync claim (compare-and-set on `next_sync_at`) | `IntegrationRepository.ClaimSyncDue` |
| Create/update validation (own sensor, no platform sensor, no credentials, engine `tenable_sc` + mode `sensor` only) | `IntegrationService` + `tenablesc.Service.ValidateConnector` |
| Command types `connector_sync`, `connector_scan` | `pkg/domain/command`, migration `000496` |
| Tool catalog row `tenable_sc` (kind `connector`, never scannable) | migration `000495`, `tool.Tool.IsConnector` |
| Source-asserted resolve | `internal/app/ingest/source_resolve.go`, `FindingRepository.ResolveSourceMitigated` |

## Security rules (enforced and tested)

- The platform never stores or sends Tenable credentials or the Tenable URL;
  the command names an instance label only.
- The command is pinned to the integration's sensor; routing hands it only to
  that sensor, and only while it reports the `tenable_sc` tool.
- The sensor must be one of the tenant's own sensors (tenant-scoped lookup);
  shared platform sensors are refused.
- Another tenant's integration id is not found (sync, update, claim).
- Results are bound to the command and its tool (RFC-040 §5.3); a sync has no
  targets, so it never changes existing assets' flags and never reopens a
  finding a person resolved.
- A mitigated row is never stored as a sighting. It resolves an open finding
  only from a command-bound report, of the same tool, on the same asset and
  identity, last seen no later than the mitigation, never `false_positive`,
  `accepted`, already resolved or from a human source.
  `INGEST_SOURCE_RESOLVE=off|dry_run|enforce` (default `dry_run`).
- Absence never resolves: sync reports are `incremental` and their command type
  is not `scan`.

## Scan launch (P1)

A scan whose `scanner_name` is `tenable_sc` is an ordinary OpenCTEM scan
(Scan → Run, schedules, retries, run history), with `scanner_config`
`{integration_id, policy_id, repository_id, zone_id?, max_scan_seconds?}`.

- **Create/update** (`scan.Service` + `tenablesc.Service.ValidateScanConfig`):
  the integration must be the tenant's own enabled connector on one of the
  tenant's own sensors; when the sensor reported a catalog (the
  `connector_sync` result), the policy, scan repository and zone must be in
  it. The sensor's allow-list is enforced again on the sensor.
- **Run** (`scan.Service.triggerConnectorScan`): targets are resolved as for
  any scan (group members, exclusions, attribution, the actor's act scope;
  a scheduled run acts as the scan's creator), then pass the active-probe
  gate once more (`ResolveDispatchTargets`, act scope on). One
  `connector_scan` command, pinned to the connector's sensor, carries the
  allowed targets and the run's pipeline keys, so the run completes or fails
  with the command like any single scan. Expiry: `max_scan_seconds` + 2 h.
- **Results**: bound to the command and its targets; `coverage_type: full`
  only when the Tenable.sc scan completed and imported. Coverage-scoped
  auto-resolve treats a completed full `connector_scan` like a scan command
  (same tool, covered assets only); a `connector_sync` never resolves by
  absence.
- **Sensor**: openctemio/sensor#131 creates the scan definition, launches it,
  polls `scanResult`, stops it on cancel or timeout, pulls the individual
  result and deletes the definition it created.

## Audit

Source-asserted resolve writes one audit entry per report:
`ingest.source_resolved` (enforce) or `ingest.source_resolve_dry_run`
(dry run), with the command id, the count and up to 200 finding ids.

## Not built yet

Coverage on the connector (P2) and the web integration page (still hidden
until the connector ships end to end).
