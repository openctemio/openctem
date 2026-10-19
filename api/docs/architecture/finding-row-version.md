# Finding write concurrency (row_version)

Status: shipped (migration 003102).

## Problem

A finding is changed by many writers: people through the API (status,
assignment, tags, severity, classification, remediation), and the platform in
the background (ingest re-sightings, the priority worker, the SLA applier,
assignment rules, automation, ticket sync). Most API mutators read the finding,
change it in memory and write every column back. Two writers working on the
same finding at the same time overwrote each other: a tags edit that read the
finding before someone resolved it wrote the old status back. Because that
write was not a person's move, the regression trigger also marked the finding a
regression and counted a reopen. Ingest enrichment had the same flaw: it read
the stored rows, merged a sighting, and wrote back the priority class, an
analyst's priority override and the SLA deadline from its stale copy.

## Design

- `findings.row_version` (`BIGINT NOT NULL DEFAULT 0`). The trigger
  `trg_findings_row_version` (`BEFORE UPDATE`, function
  `findings_bump_row_version()`) adds one on every update of the row,
  whichever writer runs it, including narrow writers and triggers on other
  tables. A trigger rather than an explicit bump in each statement, so no
  writer can forget it.
- `FindingRepository.Update` (the full-row write) carries
  `AND row_version = <version read>` for a finding read from storage. When no
  row is updated it reads the finding again, tenant-scoped: gone (or another
  tenant's id) is not found; otherwise it returns a
  `vulnerability.FindingConflictError` (wraps `shared.ErrConflict`) holding the
  stored finding, and writes nothing.
- Retry: the single-finding mutators of the finding service run through
  `vulnerability.RetryOnFindingConflict`. A lost race re-reads the finding,
  applies the change again (with all its checks) and writes, up to three
  attempts. Every such method does its finding write before any other side
  effect, so a retry repeats nothing. Background writers that change one field
  use `vulnerability.UpdateFindingRetrying` (assignment-rule priority), and
  automation tag actions use `EditFindingTags`, which adds and removes tags on
  the fresh read instead of writing a list computed earlier.
- Ingest enrichment writes only the columns it merges from a sighting. EPSS
  and KEV (threat-intel refresh), the priority class, its reason and override,
  reachability (priority worker) and the SLA deadline and status (SLA applier)
  are no longer written by it. Its batch write carries the same row_version
  predicate and returns the ids that landed; a row that moved is read and
  merged again, bounded.

## API

- Every finding response has `row_version`.
- The single-finding writes (`PATCH /findings/{id}/status`, `/classify`,
  `/severity`, `/remediation`; `POST /findings/{id}/assign`, `/unassign`,
  `/verify`, `/remediation/steps`; `PUT /findings/{id}/tags`) accept
  `If-Match: "<row_version>"` (also `W/"…"` or a bare number; `*` is ignored).
  With it the write lands only while the finding is still at that version, and
  the server does not retry: a refusal is `409` with code `FINDING_CHANGED`
  and `details` `{finding_id, row_version, status, updated_at}` of the stored
  finding. A malformed value is `400`. Without the header the server writes on
  its own read and retries a lost race.
- Bulk actions do not take If-Match. A finding whose write loses the race is
  reported as failed in the bulk result and left unchanged.

## Web

The finding detail page and drawer send the `row_version` the person sees with
status, severity and assignment changes, and the version a write returned for
the next one. On `FINDING_CHANGED` the change is reverted, the finding is
reloaded and a notice (`findings.conflict.changed`) says someone else changed
it (`web/src/features/findings/lib/finding-conflict.ts`).

## Security

Authorization is unchanged: every route keeps its gate, the service still
loads the finding through the tenant and data-scope check before writing, and
the repository write and its conflict lookup are tenant-scoped. Another
tenant's finding or one outside the caller's data scope answers `404` with or
without If-Match, never `409`, so a version probe reveals nothing. The 409
body carries only the version, status and update time of the finding the
caller just passed the scope check on; the full finding is read again through
`GET`, which applies the scope.

## Key files

- `migrations/003102_finding_row_version.up.sql`
- `pkg/domain/vulnerability/finding_row_version.go`
- `internal/infra/postgres/finding_repository.go` (`Update`, `findingConflict`, `EnrichBatchByFingerprints`)
- `internal/infra/http/handler/finding_row_version.go` (If-Match, 409)
- `internal/app/finding/vulnerability_service.go` (retry wrappers, `EditFindingTags`)
- Tests: `internal/infra/postgres/finding_row_version_db_test.go`,
  `internal/infra/http/routes/finding_row_version_db_test.go`,
  `pkg/domain/vulnerability/finding_row_version_test.go`,
  `web/src/features/findings/hooks/__tests__/use-finding-triage-conflict.test.tsx`
