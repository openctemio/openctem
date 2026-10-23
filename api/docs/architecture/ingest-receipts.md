# Import and run receipts

Design: [RFC-122](../rfcs/RFC-122-ingest-receipts.md). Related:
[finding import](finding-import.md), [sensor results ingest](../rfcs/RFC-026-sensor-results-ingest.md),
[deduplication](deduplication.md), [dashboards](dashboards.md),
[authorization matrix](authorization-matrix.md) (data scope).

Every upload and every sensor run gets a receipt: what it did to the
organization's findings. The ingest service writes it; nothing else does.

## What is shipped

| Part | State |
|---|---|
| Receipts table, per-finding action log, coverage decisions, daily ingest fact (migration `003308_ingest_receipts`) | shipped |
| Writer in ingest (every report), in coverage decisions, and for uploads (one receipt per request) | shipped |
| Retention job (`ingest-receipt-retention`) | shipped |
| Receipts API (`GET /findings/imports`, `/{id}`, `/{id}/actions`, `GET /findings/{id}/imports`), `POST /findings/imports` with 201 and the receipt, durable `Idempotency-Key` (migration `003325_idempotency_keys`) | shipped |
| Full-coverage uploads (`coverage=full` with an explicit scope) | shipped |
| Web: receipt and recent imports in the import dialog, "What this run did to findings" on the scan run page, "Last seen in" on the finding overview (en, vi) | shipped |

## Which receipt

| Ingest | Receipt (`source_kind`, `source_ref`) |
|---|---|
| A file uploaded with `POST /findings/imports` | `upload`, the receipt's own id; every file of the request shares it |
| A sensor report bound to a command of a scan run | `scan_run`, the run id: all commands of all steps add to one receipt |
| A sensor report bound to a command outside a run | `command`, the command id |
| A CI run's upload | `ci_run`, the run id |
| A server-side ingest (connector sync, feed, certificate monitor) | `connector`, its run id (`Options.SourceRun`) or a hash of the report id |
| A sensor report without a command | `sensor`, a hash of the sensor id and the report id |

The repository resolves a command to its scan run inside the writing
transaction (`commands.scan_run_step_id` → `scan_run_steps.scan_run_id`); a
command of another tenant is refused.

## How a receipt is written

`ingest.Service.Ingest` builds one delta per report at its end
(`internal/app/ingest/receipt.go`):

- `Created`: the ids the batch insert actually inserted;
- `Reopened`: the ids the auto-reopen moved back to open;
- `StillDetected`: the stored fingerprints the report sighted;
- `Closed`: the ids a source's own mitigation statement resolved, in enforce
  mode only;
- `Received`, `Skipped` (not stored for a reason: scope, exclusion,
  invalid), `Failed` (storing failed), `Suppressed`, assets created and
  updated;
- errors as `{index, code}` with the code `store_failed`.

`IngestReceiptRepository.Record` applies it in one transaction:

1. upsert the receipt by `(tenant_id, source_kind, source_ref)` (the row
   lock serializes concurrent batches of one run);
2. insert the action rows in the order created, reopened, closed, still
   detected, `ON CONFLICT (receipt_id, finding_id) DO NOTHING`, matched to
   the tenant's findings only, at most 50,000 per receipt;
3. add to the counts the rows each list actually added (past the cap, the
   rest of the list, and `actions_truncated`);
4. for a coverage decision, replace the command's row in
   `ingest_receipt_coverage` and set `coverage = full` and
   `findings_untouched` to the sum over its commands;
5. upsert the day's `dash_ingest_day` row with the same counts.

A failed write is logged and counted in
`openctem_ingest_receipt_write_failures_total{origin}`; the ingest stands.

## Coverage decisions

`EvaluateCommandCoverage` and the repository variant record a delta when the
run was eligible (a covered scan of an explicit scope): the findings it
closed (none in dry-run mode or when the blinding guard held it) and the open
findings of the covered scope (the tool, the covered assets) that none of the
run's reports named and that are still open (`CoverageUntouched`). The note
is `resolved`, `held` or `dry_run`. An ineligible run records nothing: it
proved no coverage, so its receipt stays `partial` with `untouched` null.

## Uploads

`findingimport.Service.BeginUpload` creates the receipt (status
`processing`) at the first file part, before anything is written; without it
the request fails. Every file is ingested with `Options.Receipt` set to it
and with the receipt id as report id (so `findings.scan_id`). The assets each
file wrote are stamped with it (`assets.import_id`). `FinishUpload` adds the
file-level counts (components, VEX statements, what the parsers skipped, the
files that failed as `file_<kind>`), sets the format (`mixed` for several),
and the status (`failed` when no file was imported). By default an upload
has partial coverage and closes nothing.

### Full-coverage uploads

`?coverage=full&asset_id=<id>` (1 to 100 `asset_id` values) declares the
upload a complete scan of those assets by the tool of each of its files.
It is a bulk close, so it is gated like `POST /findings/bulk/status` closing
findings: the route asks for step-up when `coverage=full`
(`requireStepUpWhenFullCoverage`), and the handler for `findings:status` and
`findings:bulk_update` (403). `min_severity` is refused with it (400): a
finding dropped below the threshold would read as fixed.
`findingimport.Service.CheckCoverage` then refuses it before anything is read
unless every asset is an asset of the organization visible to the uploader
(400, one answer for a missing and a hidden asset): inside their data scope,
and not a private program asset hidden from them, which an unrestricted
member may write to but not see. When the request has read every part,
`FinishUpload` (`closeUncovered`, `internal/app/findingimport/coverage.go`):

- refuses to close anything (`coverage_note = incomplete`, coverage stays
  `partial`) when a file failed, a finding could not be stored, the parser
  skipped a record, a file named no tool, or the request was cut short;
- checks the declaration again (`scope_changed`, nothing closed, when an
  asset left the uploader's scope or the organization while the upload ran);
- per tool: candidates are the open findings on the declared assets last
  seen by that tool, not a branch occurrence, not from a human source (pentest,
  manual, bug bounty, red team), not a leaked secret, and not reported by
  this upload (their `scan_id` is not the receipt id);
- the blinding guard holds a mass close (`held`, nothing closed);
- otherwise closes them (`resolved`, verification `covered_scan`, timeline
  "An upload that declared full coverage ... no longer reported it"),
  records them as `closed` actions, and stores what is left open in the
  scope as `untouched`.

## Reading receipts

| Route | Gate | Who sees what |
|---|---|---|
| `GET /api/v1/findings/imports` | `findings:read` | organization view (unrestricted data scope, or `dashboards:org:view`): every receipt; anyone else: only their own uploads. Filters `source_kind`, `source_ref`; unknown parameter 400 `INVALID_FILTER`; `per_page` ≤ 100 |
| `GET /api/v1/findings/imports/{id}` | `findings:read` | as the list (else 404); `by_severity` counts the actions per action and severity over findings in the caller's scope |
| `GET /api/v1/findings/imports/{id}/actions` | `findings:read` | as the list; rows only for findings in the caller's data scope and pentest visibility; filter `action` |
| `GET /api/v1/findings/{id}/imports` | `findings:read` | the finding must be in scope (404); the newest 20 receipts that acted on it: id, kind, ref, tool, action, time (no counts) |

A non-organization caller is any member whose data scope is restricted, and
also a full-data member who has hidden private-program assets: the stored
counts may include findings they cannot see. Handler:
`internal/infra/http/handler/ingest_receipt_handler.go`.

## Daily fact

`dash_ingest_day(tenant_id, day, source_kind, tool)` with `source_kind` one of
`import` (uploads), `sensor` (scan runs, commands, sensor reports), `ci`,
`connector`. Organization-wide figures; a widget applies the dashboard's
organization-view rule.

## Retention

The `ingest-receipt-retention` controller runs hourly on one replica (it
also deletes expired `idempotency_keys`):
action rows older than 90 days, run receipts not updated for 400 days (their
action and coverage rows go with them), facts older than 400 days, in
batches of 5,000 and at most 100,000 rows of each kind per pass. Upload
receipts are kept.

## Web

`web/src/features/findings/components/receipt-summary.tsx` (one component
set, token classes only):

- `ReceiptSummary`: the seven counts (untouched shows "—" under partial
  coverage) and a line saying whether the coverage could close anything,
  that a close was held, or that the action list was truncated;
- `RecentImports`: the latest five upload receipts, at the bottom of the
  import dialog before a file is chosen;
- `RunReceiptSection`: the scan run's receipt in the run sheet; nothing when
  the API returns none (a member without the organization view);
- `FindingLastSeenIn`: the newest receipt that acted on the finding, linked
  to the run page for a scan run.

Data comes from `web/src/features/findings/api/receipts-api.ts` (SWR, keyed
only inside an organization). Text is in the `findings.receipts.*` keys (en
and vi).

## Key files

- `api/migrations/003308_ingest_receipts.up.sql`
- `api/pkg/domain/ingestreceipt/receipt.go`
- `api/internal/infra/postgres/ingest_receipt_repository.go`
- `api/internal/app/ingest/receipt.go`, `coverage_autoresolve.go`
- `api/internal/app/findingimport/service.go`
- `api/internal/infra/controller/ingest_receipt_retention.go`
- `api/internal/infra/http/handler/ingest_receipt_handler.go`, `finding_import_idempotency.go`
- `api/internal/infra/postgres/ingest_receipt_read.go`, `idempotency_key_repository.go`

## Tests

- `internal/infra/postgres/ingest_receipt_repository_db_test.go`: one receipt
  per run with no double counting, the action log and the fact; tenant
  isolation (ids and fingerprints of another tenant, another tenant's
  command); command to scan run; a coverage decision evaluated twice; the cap;
  upload start and finish; retention.
- `internal/infra/http/routes/finding_import_receipt_db_test.go`: a partial
  re-upload closes nothing and counts still detected.
- `tests/integration/ingest_receipt_run_test.go`: a clean covered sensor run
  records still detected, closed and untouched.
- `internal/infra/http/routes/ingest_receipt_read_db_test.go`: organization
  view against restricted member, own uploads only, 404 for others' and
  another tenant's receipts, scoped actions and severity counts, a finding's
  receipts in scope only; unknown parameter 400, `per_page` capped.
- `internal/infra/http/routes/finding_import_idempotency_db_test.go`: replay
  with another boundary and file name (same receipt, nothing imported),
  reuse 422, another member's key independent, store down 503 with nothing
  imported.
- `internal/infra/postgres/idempotency_key_repository_db_test.go`: claim,
  pending, done, takeover of an expired key, a lost claim cannot finish or
  release, purge.
- `internal/infra/http/routes/finding_import_coverage_db_test.go`: refusals
  (no `findings:status`, no `findings:bulk_update`, `min_severity`, more than
  100 `asset_id` values, unknown asset, no scope, scope without full, asset
  outside the uploader's scope, a private program asset hidden from an
  administrator) close nothing; a full-coverage subset upload (one asset
  named twice) closes the finding it left out, with `closed 1`, `untouched 0`.
- `internal/infra/http/routes/finding_import_stepup_test.go`: step-up only
  for `coverage=full`.
- `internal/app/findingimport/coverage_test.go`: a failed file, a finding not
  stored, a skipped record, a file naming no tool, the blinding guard, a
  request cut short and a scope that changed close nothing.
- `internal/app/ingest/receipt_test.go`: source mapping, delta contents,
  coverage decisions (enforce, dry run, ineligible).
