# Finding sightings: who reported a finding

A finding is one row per tenant and fingerprint, and the fingerprint does not
include the tool: the same CVE on the same host reported by a scan run, an
upload and a connector is one finding
([ADR-004](decisions/004-finding-provenance.md)). Who reported it is therefore
a property of each **sighting**, not of the finding. `findings.source` stays
the technique (sast, dast, va, ...); `findings.ingest_channel` stays the coarse
channel of the first writer. What each source reported (its title, text,
severity, native identity, scores) is kept per source in
[finding source records](finding-source-records.md).

## Model

`finding_sightings` holds one row per finding and **source**:

| Key column | Meaning |
|---|---|
| `channel` | `scan` (a sensor in a scan run), `task` (a sensor command outside a run), `sensor` (an unsolicited sensor report), `upload`, `ci`, `connector`, `platform` (the version matcher); `unknown` only on backfilled rows |
| `sensor_id` | the organization's own sensor; NULL for non-sensor channels and for a shared platform sensor |
| `sender` | the CI repository or connector source name; `platform` for a shared sensor; empty otherwise |
| `tool` | the reporting tool |
| `scan_id` | the scan definition of a scan run |

The key is `UNIQUE NULLS NOT DISTINCT (tenant_id, finding_id, channel,
sensor_id, sender, tool, scan_id)`. Each row also keeps `first_seen_at`,
`last_seen_at`, `seen_count` (receipts that saw it), the last receipt, source
ref, run, step run and command, the tool version, and `backfilled`.

**Bounded growth.** A repeat of a source updates its row; repeats within one
receipt (several reports or segments of one run) change nothing, so a run
writes each sighting at most once. At most 64 sources per finding
(`ingestreceipt.MaxSightingsPerFinding`): a new source past the cap is not
recorded, an existing one still moves. Rows live as long as their finding
(FK cascade); a merge of duplicate findings moves the loser's sources to the
survivor (a source the survivor already has keeps the survivor's row).

## Write path

Sightings are written in the transaction of the receipt
([ingest-receipts.md](ingest-receipts.md)), by
`IngestReceiptRepository.Record` (`internal/infra/postgres/finding_sightings.go`).
Every channel that books a receipt therefore records its sightings: sensor
protocol v2 and v3 segments, uploads, CI runs, connector and platform imports,
the version matcher. The created, reopened, policy-decided (suppressed, held)
and still-detected findings of a delta are sightings; a closure (a coverage
decision, a source's own mitigation statement) is not.

All joins are pinned to the receipt's tenant: the findings (by id or
fingerprint), the command, its step and run (and through it the scan), and
the sensor. A sensor id that is not one of the tenant's own sensors (a shared
instance sensor, or any other id) is stored as sender `platform` with no id, so
a tenant never sees another tenant's or the platform's sensor ids.

## Read path

- `GET /api/v1/findings/{id}/sightings` (`findings:read`): the finding's
  sources, last seen first. `datascope.AssertFinding` first (404 outside the
  caller's data scope); another tenant's id is 404. The sensor (id and name)
  is in the answer only with `sensors:read`, a scan's name only with
  `scans:read`. The last receipt is linked only while it exists (run receipts
  are purged after 90 days).
- The finding page's "Seen by" section reads it
  (`web/src/features/findings/components/detail/finding-seen-by.tsx`).

## Filters

The findings registry (`pkg/domain/vulnerability/finding_fields.go`) has:

| Param | Meaning | Index |
|---|---|---|
| `seen_by_sensor_id` | a sensor of the tenant reported it; needs `sensors:read` (otherwise an unknown field) | `idx_finding_sightings_sensor` |
| `seen_by_scan_id` | a run of the scan reported it | `idx_finding_sightings_scan` |
| `seen_in_run_id` | the run's receipt recorded it (created, still detected, reopened, decided), kept 90 days | `ux_ingest_receipts_source` + `pk_finding_ingest_actions` |
| `seen_by_tool` | the tool reported it, from any channel | `idx_finding_sightings_tool` |
| `seen_by_channel` | the channel reported it | `idx_finding_sightings_channel` |
| `retired_source_only` | every source that reported it is a retired one ([source retirement](source-retirement.md)) | `(tenant_id, finding_id)` |

Each compiles to `findings.id IN (subquery)` with the tenant predicate inside
the subquery, so the data scope and the pentest member visibility still apply
to every findings row: a filter only narrows what the caller already sees and
cannot be used to learn about findings outside the scope.
`TestFindingSightings_FiltersUseIndexes_DB` checks the plans on a seeded table.
The run, scan and sensor pages link to the filtered list.

## Backfill

The migration derives sightings for existing findings, marked
`backfilled = true` (shown as "From earlier records"):

1. from `finding_ingest_actions` (90 days), joined to the receipt and, when the
   receipt has exactly one tool row, its tool and sender; a scan-run receipt
   gives the run and scan;
2. for findings the receipt log does not name, from the finding row: an
   upload receipt id in `scan_id` (upload), the `version-match` tool
   (platform), a sensor with a scanner or collector channel (sensor), a CI
   commit (ci), an integration channel (connector), otherwise `unknown` with
   the tool.

Findings a person entered (`ingest_channel = manual`, pentest) get none.

## Not yet built

- "First reported by", "only reported by X" and "last seen by X more than N
  days ago" filters, and sightings of a finding a person enters through the API.
- Export fields: a sighting exports its channel, tool and natural sender (CI
  repository, connector source) and no internal sensor, scan or run ids
  (CTIS carries no internal ids).
