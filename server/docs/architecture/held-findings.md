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

A later sighting of a held finding without a hold releases it (`unchecked`); a held sighting of a finding that
was not held changes nothing (`finding_verification_columns.go`).

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

One `finding_held_critical` notice per hold that held at least one critical finding (default on for new
integrations), with the count and the reason. It is the only message a held critical finding sends until it is
checked.

## Live impact

The migration adds two columns with constant defaults (a catalog change, no rewrite, no backfill) and validates
two CHECKs under SHARE UPDATE EXCLUSIVE; the index is built concurrently. Measured on a synthetic dataset (one
tenant with 1M findings, 1 % held): see the pull request that shipped it.
