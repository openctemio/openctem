# Scan lifecycle: Scan → Run → Task

> Last updated: 2026-10-03. Design: [RFC-046](../rfcs/RFC-046-scans-redesign.md)
> (status audit in its [appendix A](../rfcs/RFC-046-appendix-status-audit.md)).
> Dispatch details: [RFC-030](../rfcs/RFC-030-scan-work-distribution.md).
> Older component walkthrough: [scan-orchestration.md](scan-orchestration.md).

This page describes how a scan becomes work on a sensor and how its outcome is
recorded: first the model every change now moves towards, then where the code
stands today, so a reader can tell which parts are real.

## 1. The model

```
Scan (definition) ──fires──▶ Run (one occurrence) ──is cut into──▶ Task (one tool, a slice of targets)
  targets: selection            trigger, scheduled_for               attempt, lease (epoch), sensor
  engine spec (stages)          status, deadline                     status, coverage, report ids
  schedule: rrule + tz          progress, unfinished targets
```

- **Scan**: what to scan (a selection resolved through the one target gate,
  RFC-042 §6.11), how (an engine spec over the stage catalogue, RFC-046 §5),
  when (rrule + timezone, minimum 15 minutes, overlap = skip). Quick scans are
  ad-hoc scans (`scans.ad_hoc`), saved on request.
- **Run**: one firing of a scan. Exactly one run per scheduled occurrence
  (`UNIQUE(scan_id, scheduled_for)`). Triggers: `schedule`, `manual`, `api`,
  `ci`, `retest`, `automation`, `rollover`.
- **Task**: one unit a sensor claims under a lease: today one command of a
  step; with RFC-030 Phase 2, a chunk cut at claim time.

### 1.1 Run states

| Status | Meaning | Terminal | Counted as |
|---|---|---|---|
| `pending` | Created, no task claimed yet | no | — |
| `running` | At least one task claimed or started | no | — |
| `completed` | Every task completed | yes | success |
| `partial` | Some tasks completed, some failed, or the deadline passed with work done; results kept, unfinished targets recorded | yes | partial |
| `failed` | No task completed (all failed, or nobody claimed within 4 h scheduled / 1 h interactive) | yes | failure |
| `timeout` | Deadline passed and no task completed | yes | failure |
| `canceled` | Stopped by a user with `scans:write` | yes | not counted in the success rate |

A terminal run never changes again, and neither does a terminal step run: a
late or duplicate sensor result, a cancel racing a completion or the reaper
cannot reopen one, recount its findings or record its outcome twice.

### 1.2 What happens when

| Event | Effect |
|---|---|
| Occurrence due | The scheduler claims it (compare-and-set on `next_run_at`, plus the occurrence key on the run), skips it if the scan's previous run is still active, else creates the run |
| Trigger | Targets resolved through the target gate; routed to zones; tasks created; the run starts |
| Sensor poll | Claims tasks it may run (verified tool, zone, capacity), lease + epoch set in the same update |
| Heartbeat | Renews leases of tasks the sensor still runs; returns `cancel_command_ids` for those it no longer holds |
| Task completes | Results ingested (idempotent report ids); coverage-scoped auto-resolve for that task's targets (dry-run by default); the step and run settle when their last task settles |
| Deadline | Queued tasks dropped, leased tasks canceled, run ends `partial` or `timeout`, unfinished targets recorded for the next occurrence |
| Cancel | Run → `canceled`; open step runs and tasks canceled in one statement, leases cleared (never re-queued); the holding sensor is asked to ring within 5 s and gets `cancel_command_ids`; an offline sensor gets them when it reports the task again; canceling again is a no-op |
| Failure | Classified: permanent codes never retried; lost work and timeouts retried twice with backoff; others by the scan's `max_retries` |

## 2. Where the code stands (2026-10-03)

| Part | State | Where |
|---|---|---|
| Runs and tasks | `pipeline_runs`, `step_runs`, `commands` | `api/internal/app/pipeline/run.go`, `api/internal/app/scan/trigger.go`, `zones.go` |
| Run terminal guard | done | `api/internal/infra/postgres/pipeline_run_repository.go` (`terminalRunStatusesSQL`) |
| Step terminal guard | RFC-046 P1.1 (first implementation PR) | same file |
| `partial` | done: settle matrix (P1.2) and deadline → `partial` (P1.3) | `api/internal/app/pipeline/run.go`, `pipeline_run_repository.go` (`MarkTimedOutRuns`) |
| Deadline + rollover | done: `deadline_at` fixed when the run starts (scan timeout, 24 h cap); at the deadline open commands fail and lose their lease (the sensor is told to stop on its next heartbeat), unfinished targets (≤ 10,000, dispatch order) are recorded; the next **scheduled** run plans them first, reordering only targets the gate resolved again | `pipeline_run_repository.go` (`runDeadlineSQL`, `MarkTimedOutRuns`, `LatestRollover`), `api/internal/app/scan/rollover.go` |
| Occurrence claim | compare-and-set on `next_run_at`; occurrence key planned (P1.5) | `api/internal/app/scan/scheduler.go`, `scan_repository.go` (`ClaimScheduledRun`) |
| Overlap skip | done; checked in the run-insert transaction under the scan row lock (P1.6), so a manual trigger cannot slip in between | `scheduler.go` (`SkipIfRunning`), `pipeline_run_repository.go` (`CreateRunIfUnderLimit`, `ErrScanRunActive`) |
| rrule | `schedule_type` `rrule`: an RFC 5545 rule (RRULE parts only, e.g. `FREQ=WEEKLY;BYDAY=MO;BYHOUR=2`) in `scans.schedule_rrule`, evaluated in `schedule_timezone` from a fixed anchor (2024-01-01 00:00 local, so INTERVAL counts the same everywhere; no BYHOUR means midnight); refused on save if it does not parse, has no future occurrence, uses SECONDLY/BYSECOND/COUNT/DTSTART, or fires more often than every 15 minutes over the next year. Legacy daily/weekly/monthly/crontab still work; their backfill to rules is pending. Crontabs and rules more frequent than 15 minutes are refused; legacy ones are spaced when claimed; missed occurrences are skipped (`skipped_misfire`) | `api/pkg/domain/scan/rrule.go`, `entity.go` |
| Claim + leases + fencing | dispatch order: priority class (one class up per 30 min waited, never into critical), then round-robin across runs, then age; claim-1 by id, and claim-N for a v2 sensor that names the `capacity` feature (`GET /api/v2/sensor/commands` returns its commands already claimed, at most `max_jobs` minus the scans it holds, one `UPDATE … FOR UPDATE SKIP LOCKED`); platform-sensor tenant fair share still to do | `command_repository.go` (`ClaimForSensor`), `command_lease.go`, `api/pkg/domain/command/lease.go` |
| Cancel to sensor | via heartbeat `cancel_command_ids`; doorbell busy interval while a held task was just canceled; run cancel closes steps + tasks (`CloseCanceledRun`) | `command_lease.go` (`CommandsToCancel`), sdk-go `pkg/core/doorbell.go` |
| Abort unclaimed | done (4 h / 1 h) | `pipeline_run_repository.go` (`AbortUnclaimedRuns`), `controller/scan_timeout.go` |
| Retry classes | done (run-level) | `api/pkg/domain/pipeline/failure.go`, `pipeline_run_repository.go` (`ListPendingRetries`) |
| Coverage auto-resolve | done, **stays dry-run** (D-22 postponed until the research 18 P2 closure evaluator) | `api/internal/app/ingest/coverage_autoresolve.go`, `INGEST_COVERAGE_AUTO_RESOLVE` |
| Stage chaining | not yet (every step scans the seed targets) | RFC-046 §5.2 |
| Automations | in-process executor fed by callbacks; outbox planned (P2). Cancel skips open steps and the executor stops before its next step; finished runs and steps are never rewritten | `api/internal/app/workflow/` |
| `scan_sessions` | written by nothing; retired in P2 | `api/internal/app/scan/session.go` |

## 3. Things that are deliberately not wired

- **Scope schedules** (`scan_schedules`, Scoping › Schedules) are **inert by
  Scoping IA decision D10**. Nothing reads `ListDueSchedules`; do not connect
  them to the scheduler or the dispatcher. Schedules belong to the Scan.
- **Interactsh** is off on the sensor unless the sensor-local policy and the
  job both allow it (RFC-040, RFC-046 D6).
- **Adaptive chunk sizing** is deferred (RFC-046 D9, RFC-030 Phase 2).

## 4. Invariants (each has a test)

1. One run per scheduled occurrence.
2. A terminal run or step run never changes.
3. A task's results are accepted only from the sensor holding its live lease
   (epoch match), for that task's tool and targets.
4. Auto-resolve never acts on a failed, canceled, expired, timed-out or
   partially covered task, and only on the targets the task covered.
5. Every path that turns a selection into work goes through the one target
   gate.
6. Every query is tenant-scoped from the credential; a foreign id is a 404.
