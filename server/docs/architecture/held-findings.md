# Held findings

A finding matched while its target was throttling or blocking the scan may be the target's limit page, not the
application. It is **held**: kept with its evidence and listed, but out of risk scores, SLA escalation,
notifications and tickets until it is checked. Design: [RFC-158](../rfcs/RFC-158-held-findings.md).

## State

`findings.verification_state` is one of:

| state | meaning |
|---|---|
| `unchecked` | no check either way (default; every finding written before the state existed) |
| `held` | matched while the target throttled or blocked the scan; see `hold_reasons` |
| `verified` | a check reproduced the match on a clean answer (planned: automatic re-checks) |
| `not_reproduced` | checks did not reproduce it; kept, never an automatic false positive (planned) |

`findings.hold_reasons` holds the codes behind a hold, from a fixed set (database CHECK): `edge_block_page`,
`throttled_response`, `soft_404`, `target_throttled`, `timing_based`, `oob_weak`. Only `target_throttled` is
set today; the others come with the sensor's per-finding screen (planned).

The API returns `verification_state` and `hold_reasons` on a finding. The findings list and the query language
filter on `verification_state` (`?verification_state=held`); the partial index `idx_findings_tenant_held` serves
that filter.

## Coverage gaps

A scan command's result lists coverage gaps per host (`pkg/domain/scanrun/coverage_gaps.go`). The reasons
`throttled`, `blocked`, `edge_protected`, `rate_floor` and `catch_all` hold findings
(`vulnerability.HoldGapReasons`); `breaker_open` and `proxy_unavailable` do not (the host did not answer, or the
sensor's path failed: nothing was matched on them).

## When a finding is held

`internal/app/ingest/held.go`, repository `internal/infra/postgres/finding_hold.go`:

- **At ingest of a command's report**, when the command's result is already in: right after the findings are
  written and before their created events, so a held finding is never announced.
- **When the command's coverage is evaluated** (`EvaluateCommandCoverage`), for reports that were ingested before
  the result arrived. Their new-finding event may already have been sent; the hold still removes them from scores,
  SLA escalation and tickets.

Only findings the command's reports sighted **first** (`first_detected_at` at or after the report was received)
on a gap host, still `unchecked`, are held. A finding that was there before keeps its state; a verified one is
never held. The update returns the rows it changed, so a second call holds nothing and announces nothing.

A held sighting of a finding that was not held changes nothing (`finding_verification_columns.go`).

## When a hold is released

A later run that sights a held finding again releases it (`unchecked`, `hold_reasons` empty):

- **When a later command's coverage is evaluated** (`releaseRunFindings`, repository `ReleaseRunFindings`). Every
  sighting path (new-finding insert, enrichment `EnrichBatchByFingerprints`, sighting-only
  `UpdateScanIDBatchByFingerprints`) writes the report into `scan_id`; the held findings whose `scan_id` is a
  report of the command, on an asset whose host the command's result does **not** name in a holding gap, are
  released. A result without gaps releases every such finding. Only holds whose every reason is `target_throttled`
  are released this way: a hold from the matched response itself stays until that response is checked.
- Nothing is released when the command did not complete, when its result says the run stopped, or when its gap
  list is missing, unreadable or cut (`coverage_gaps_total` above what it lists, or an entry with an unknown
  reason): a throttled host may be missing from it.
- **On the insert path's conflict**, a clean sighting releases a held finding
  (`findingVerificationConflictSQL`).

A released finding sends its created side effects then, once: notifications, automation rules and automatic
tickets (`announceReleased`, through the same side-effect queue as new findings; a finding decided, closed,
branch-only or already reported meanwhile sends none). The release re-enters it in risk inputs and SLA escalation
(the queries filter on the state), and the asset risk trigger queues its asset for a rescore.

## What a held finding is kept out of

| area | where |
|---|---|
| asset risk inputs (severity counts), risk rollups and top contributors | `asset_repository.go`, `asset_risk_queue_repository.go` |
| business unit and asset group counts | `business_unit_repository.go`, `asset_group_repository.go` |
| dashboard open, overdue and executive counts; KEV critical counts | `dashboard_repository.go`, `finding_repository.go` |
| emerging-threat alerts | `threat_alert_repository.go` |
| SLA breach and at-risk escalation (the deadline is kept) | `internal/infra/controller/sla_escalation.go` |
| new-finding events: notifications, automation rules (every created-event path) | `internal/app/ingest` (`withoutHeld`) |
| priority-escalation notices | `internal/app/finding/priority_change_outbox_publisher.go` |
| automatic tickets: the Jira policy holds it (`below_threshold`, detail `held`) and releases it once checked; an automation `create_ticket` step is skipped (`finding_held`) | `pkg/domain/ticketpolicy`, `internal/app/automation/action_handlers.go` |

Each SQL path adds `vulnerability.NotHeldSQL(col)` next to the open-status predicate. A person can still open,
triage, assign or ticket a held finding by hand.

## Notice

At most one `finding_held_critical` notice per scan command that held at least one critical finding (default on
for new integrations), with the count of the first hold and the reason. A command's reports are held one by one
and its evaluation runs from both ends, so the notice is keyed on the command (`aggregate_type` `scan`,
`aggregate_id` the command) and written under a transaction-scoped advisory lock only when the command has none
yet (`OnceHeldNotice`). It is the only message a held critical finding sends until it is checked or released.

## Asset rescore

Holding and releasing change an asset's risk inputs, so the findings update trigger of the asset risk queue
(`trg_findings_asset_risk_update`) also watches `verification_state` (migration
`finding_verification_state_risk_trigger`).

## Live impact

- `finding_verification_state` adds two columns with constant defaults (a catalog change, no rewrite, no
  backfill) and two CHECKs NOT VALID (no scan): its ACCESS EXCLUSIVE lock lasts only for the catalog change.
- `finding_verification_state_index` builds the partial index concurrently.
- `finding_verification_state_validate` validates both CHECKs in a migration of its own (the runner applies one
  file per transaction, so validating in the ALTER's file would scan under the ALTER's lock): SHARE UPDATE
  EXCLUSIVE, reads and writes go on.
- `finding_verification_state_risk_trigger` recreates the asset risk trigger (short lock, no scan).

Measured on a synthetic dataset (one tenant with 1M findings, 1 % held): see the pull request that shipped it.
