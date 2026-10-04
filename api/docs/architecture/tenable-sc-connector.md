# Tenable.sc sensor connector

Design: [RFC-047](../rfcs/RFC-047-tenable-sc-sensor-connector.md). This page
describes what is built and where it lives.

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

## Not built yet

`connector_scan` (RFC-047 P1), coverage on the connector (P2), and the web
integration page (still hidden until the connector ships end to end).
