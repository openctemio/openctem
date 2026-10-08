# Sensor result binding and the results quarantine

> RFC: RFC-040 §5.3 and §6.1 group (C) (mutual distrust between the platform
> and sensors; decision Q6 (a)). Protocols:
> [RFC-026](../rfcs/RFC-026-sensor-results-ingest.md) (v2 results),
> [sensors.md](sensors.md). Migration: `000287_sensor_result_quarantine`.

A sensor key used to be enough to write and change any asset and finding of
its tenant, with no job behind it. Since RFC-040 group (C) every sensor report
is classified by the authority behind it, and only a report bound to a command
the sensor holds may change what already exists.

## The rule

| Report | What it may do |
|---|---|
| **Bound**: names a command assigned to the submitting sensor and open (acknowledged or running, or finished less than 15 minutes ago) | Everything it did before, limited to the command: it changes existing assets the command's targets cover, reopens findings a person resolved on them, and auto-resolves only on those assets. Its tool must be the command's tool. |
| **Cross-sensor or stale command**: names a command of another sensor, one finished long ago, or one that does not exist | Refused: v1 `404 COMMAND_NOT_FOUND`, v2 `command-not-found`. Nothing is stored. |
| **Unsolicited**: names no command, from a **collector** or **CI runner** (`type` `collector`, `runner`) | Applied with the unsolicited limits (below), whatever the tenant's mode. |
| **Unsolicited**, any other role (`worker`, `sensor`), tenant mode **warn** | Applied with the unsolicited limits; the ingest audit entry carries `unsolicited_warned: true`, the response `"unsolicited_warned": true`, and `sensor_unsolicited_results_total{outcome="warned"}` counts it. |
| **Unsolicited**, any other role, tenant mode **quarantine** | Stored in the quarantine, not applied. v1 answers `422 RESULTS_QUARANTINED` with `details.quarantine_id`; v2 accepts the segments and the report status counts every item under `quarantined`, with item error `quarantined_no_command`. Audited as `sensor.results_quarantined`. |
| Server-side ingest (tenant upload, DefectDojo, an accepted quarantine item) | Trusted: unchanged behavior. |

**Unsolicited limits.** An unsolicited report may create assets and findings
and update open findings. It never changes an existing asset: no exposure,
`is_internet_accessible`, compliance scope, data classification, PII/PHI,
owner reference, identifiers, name, tags or properties, and no reactivation
(an active asset only gets its last-seen time; an inactive, stale or archived
one is not touched). It never reopens a finding a person resolved (status
`resolved`/`verified` with any `resolution_method` but `scan_verified`); a
finding the scanner auto-resolved still reopens when it is seen again. In a
tenant whose mode is **quarantine** it never auto-resolves anything; in
**warn** mode it auto-resolves as before. The response counts what was held
back: `assets_limited`, `reopens_withheld`
(`sensor_result_changes_withheld_total{kind}`).

**Coverage.** A command covers an existing asset when one of its payload
targets (`targets`, `target`) names the asset's host (or one of its IPs), a
parent domain of it, a CIDR containing its IP, or, for assets with a path
(repositories), the same path or a parent path (`github.com/acme` covers
`github.com/acme/app`). A command with no targets covers nothing: its report
creates and updates findings but changes no existing asset.

Also part of group (C):

- A sensor with no declared and no reported tools no longer auto-resolves
  (it could close any tool's findings with a "full" report).
- Validation evidence without the validate command assigned to the sensor
  (`command_id`) is refused with `403 COMMAND_REQUIRED`, unless the tenant
  turns on `allow_advisory_evidence`; it is then stored as advisory.
- A sensor reads only the reports it sent (`GET /api/v2/sensor/results/{report_id}`).
  The v1 ingest-job and scan-session routes were retired with protocol v1.

## How a report names its command

| Path | Carries the command id | Who sends it today |
|---|---|---|
| v2 `PUT /api/v2/sensor/commands/{command_id}/results/{report_id}` | yes, in the path | every sensor on sdk-go ≥ v0.10.0 (sensor ≥ v0.6.0, so all deployed v0.6.x and v0.7.0 sensors) for results produced while running a command (`core.WithCommandID` on the executor context, kept by the outbox) |
| v2 `PUT /api/v2/sensor/results/{report_id}` | no | sdk-go when the command is no longer open (it re-sends unbound after `command-not-found`), and pushes outside a command |

So scheduled scans, scan workflow steps and quick scans run by current sensors are
bound and apply as before. A v1 report bound with the header is processed
synchronously even when `INGEST_MODE=async` (the queue keeps no binding).

## Modes and defaults

`sensor_result_policies` holds one row per tenant: `mode` (`warn` |
`quarantine`) and `allow_advisory_evidence` (default false). Migration 000317
gives every tenant that exists at upgrade time `warn`, because sensors on old
SDKs and the v1 fallback cannot name their command. A tenant without a row
(every tenant created later) is on `quarantine`. An administrator switches
with `PUT /api/v1/sensors/result-policy` (`sensors:write`, audited as
`sensor.result_policy_updated`). RFC-040 §7: the switch is forced to
quarantine at the bearer-key sunset.

## The quarantine

`sensor_result_quarantine` stores the CTIS report (one row per v1 request or
v2 segment) as JSON, with the sensor, route, report id, tool and counts. At
most 1000 pending items per tenant, 200 per sensor, 16 MiB per item; beyond
that the report is refused (`422 RESULTS_QUARANTINE_FULL`, v2 item error
`quarantine_full`), so a stolen key cannot fill the database.

| Endpoint | Permission | |
|---|---|---|
| `GET /api/v1/sensors/quarantined-results?status=&sensor_id=&page=&per_page=` | `sensors:read` | newest first, no payload |
| `GET /api/v1/sensors/quarantined-results/{qid}` | `sensors:read` | with a preview: up to 100 assets and findings |
| `POST /api/v1/sensors/quarantined-results/{qid}/approve` | `sensors:write` | applies it as a person's decision: may change the existing assets it names and reopen findings, never auto-resolves; once only (409 after) |
| `POST /api/v1/sensors/quarantined-results/{qid}/reject` | `sensors:write` | drops the payload; once only |
| `GET`/`PUT /api/v1/sensors/result-policy` | `sensors:read` / `sensors:write` | the mode and `allow_advisory_evidence` |

Accept and discard are audited (`sensor.results_accepted`,
`sensor.results_discarded`).

## Code

| What | Where |
|---|---|
| Binding, coverage, roles | `api/internal/app/ingest/binding.go` |
| Gate, quarantine, review, `OpenCommand` (shared with the v2 receiver) | `api/internal/app/ingest/quarantine.go` |
| Limited asset merge | `api/internal/app/ingest/processor_assets.go` (`mergeInto`) |
| Human-resolved reopen guard | `api/internal/app/ingest/processor_findings.go` (`withoutHumanResolved`), `api/internal/infra/postgres/finding_human_resolved.go` |
| Auto-resolve gating | `api/internal/app/ingest/service.go` (v1), `v2.go` (`CommitV2Report`, `coveredByCommand`) |
| v2 segment gate | `api/internal/app/ingest/v2_jobs.go` (`processSegment`) |
| v1 header and response codes | `api/internal/infra/http/handler/ingest_handler.go` |
| Review API | `api/internal/infra/http/handler/sensor_result_handler.go` |
| Store | `api/internal/infra/postgres/sensor_result_repository.go`, `api/pkg/domain/sensorresult` |

## Not yet

- A review page in the console (the API above is complete).
- sdk-go: send `X-OpenCTEM-Command-ID` on its v1 fallback.
- Discovered assets outside the command's targets become RFC-036 candidates
  instead of assets (RFC-040 §5.3); today a bound report may still create
  them.
- `simulation_run_id` and `target.asset_id` on validation evidence, telemetry
  `correlation_id` and credential ingest are not yet bound (RFC-040 S3e, S3f).
