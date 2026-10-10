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
| `partial` | Some tasks completed, some failed, or the deadline passed with work done; results kept, unfinished targets recorded. Also when every step finished but zone routing left targets uncovered (`uncovered_targets`): the run did not scan everything it was asked to | yes | partial |
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
| Runs and tasks | `scan_runs`, `scan_run_steps`, `commands`; a run's tasks are its commands (by `payload.scan_run_id`, index `idx_commands_pipeline_run`), read with `CommandRepository.ListRunTasks` / `TaskSummaries` and returned as `task_summary` (run list) and `tasks` (run, first 200; targets counted, never listed; a platform sensor is never named) | `api/internal/app/pipeline/run.go`, `api/internal/app/scan/trigger.go`, `zones.go` |
| Run terminal guard | done | `api/internal/infra/postgres/pipeline_run_repository.go` (`terminalRunStatusesSQL`) |
| Step terminal guard | RFC-046 P1.1 (first implementation PR) | same file |
| `partial` | done: settle matrix (P1.2) and deadline → `partial` (P1.3) | `api/internal/app/pipeline/run.go`, `pipeline_run_repository.go` (`MarkTimedOutRuns`) |
| Deadline + rollover | done: `deadline_at` fixed when the run starts (scan timeout, 24 h cap); at the deadline open commands fail and lose their lease (the sensor is told to stop on its next heartbeat), unfinished targets (≤ 10,000, dispatch order) are recorded; the next **scheduled** run plans them first, reordering only targets the gate resolved again | `pipeline_run_repository.go` (`runDeadlineSQL`, `MarkTimedOutRuns`, `LatestRollover`), `api/internal/app/scan/rollover.go` |
| Occurrence claim | compare-and-set on `next_run_at`; occurrence key planned (P1.5) | `api/internal/app/scan/scheduler.go`, `scan_repository.go` (`ClaimScheduledRun`) |
| Overlap skip | done; checked in the run-insert transaction under the scan row lock (P1.6), so a manual trigger cannot slip in between | `scheduler.go` (`SkipIfRunning`), `pipeline_run_repository.go` (`CreateRunIfUnderLimit`, `ErrScanRunActive`) |
| rrule | `schedule_type` `rrule`: an RFC 5545 rule (RRULE parts only, e.g. `FREQ=WEEKLY;BYDAY=MO;BYHOUR=2`) in `scans.schedule_rrule`, evaluated in `schedule_timezone` from a fixed anchor (2024-01-01 00:00 local, so INTERVAL counts the same everywhere; no BYHOUR means midnight); refused on save if it does not parse, has no future occurrence, uses SECONDLY/BYSECOND/COUNT/DTSTART, or fires more often than every 15 minutes over the next year. Legacy daily/weekly/monthly/crontab still work; their backfill to rules is pending. Crontabs and rules more frequent than 15 minutes are refused; legacy ones are spaced when claimed; missed occurrences are skipped (`skipped_misfire`) | `api/pkg/domain/scan/rrule.go`, `entity.go` |
| One-off run | `schedule_type` `once` with `run_at` (RFC 3339; stored in `scans.schedule_run_at`, migration 001670): the scan runs once at that instant, then has no next run (it is not reported as an inert schedule). `run_at` must be between a minute and a year ahead on save; `schedule_timezone` only says how to show it. An edit that sends the stored run back unchanged keeps it, even once it has run. A one-off run missed by more than an hour (the platform was down) is skipped and recorded (`skipped_misfire`), never started at a time nobody chose; a freeze window defers it like any run. Import turns a one-off run that is no longer ahead into a manual scan. The wizard sends the viewer's timezone (or the one chosen) with every schedule; before, every time was read as UTC and "Schedule for later > Once" saved a manual scan that never ran | `api/pkg/domain/scan/once.go`, `web/src/features/scans/lib/zoned-time.ts` |
| Schedule preview | done: `POST /api/v1/scans/schedule-preview` (`scans:read`, stateless, reads and stores nothing) validates a schedule with the save rules and lists its next 1-10 occurrences (`Scan.UpcomingOccurrences` = the scheduler's `OccurrenceAfter` repeated) as RFC 3339 in the scan timezone. The web shows them on the scan page, the scan drawer and the wizard's schedule step (with the viewer's local time when it differs); a refused schedule shows the save error inline. The browser never evaluates a cron or RRULE itself | `api/internal/app/scan/schedule_preview.go`, `web/src/features/scans/components/schedule-preview.tsx` |
| Claim + leases + fencing | dispatch order: priority class (one class up per 30 min waited, never into critical), then round-robin across runs, then age; claim-1 by id, and claim-N for a v2 sensor that names the `capacity` feature (`GET /api/v2/sensor/commands` returns its commands already claimed, at most `max_jobs` minus the scans it holds, one `UPDATE … FOR UPDATE SKIP LOCKED`); platform-sensor tenant fair share still to do | `command_repository.go` (`ClaimForSensor`), `command_lease.go`, `api/pkg/domain/command/lease.go` |
| Cancel to sensor | via heartbeat `cancel_command_ids`; doorbell busy interval while a held task was just canceled; run cancel closes steps + tasks (`CloseCanceledRun`) | `command_lease.go` (`CommandsToCancel`), sdk-go `pkg/core/doorbell.go` |
| Abort unclaimed | done (4 h / 1 h) | `pipeline_run_repository.go` (`AbortUnclaimedRuns`), `controller/scan_timeout.go` |
| Retry classes | done (run-level) | `api/pkg/domain/pipeline/failure.go`, `pipeline_run_repository.go` (`ListPendingRetries`) |
| Coverage auto-resolve | done, **stays dry-run** (D-22 postponed until the closure evaluator ships) | `api/internal/app/ingest/coverage_autoresolve.go`, `INGEST_COVERAGE_AUTO_RESOLVE` |
| Controller leases | done (P1.8): `controller_leases` (name, holder, epoch, expires_at); take by compare-and-set on expiry, renew every third of the TTL, epoch bumps on every take; `Exclusive` controllers skip a tick when another replica holds the lease and stop if they lose it | `api/internal/infra/postgres/controller_lease_repository.go`, `api/internal/infra/controller/controller.go` |
| Workflow version pin | done (P0-10): when a workflow run starts, the workflow's settings and steps are saved as an immutable version in `scan_workflow_versions` unless the latest version has the same `spec_digest` (sha256 of the spec without the builder layout); the run records `scan_workflow_version` and `spec_digest` and every later read of its workflow (advance, fail-fast, stall repair, stage chaining) uses that version, so an edit made while it runs changes the next run only. A pinned version that cannot be read stops the run's progress instead of falling back to the live workflow. Runs from before versions and runs without a workflow stay unpinned. Versions go with their workflow and tenant | `api/pkg/domain/scanworkflow/version.go`, `api/pkg/domain/scanrun/pin.go`, `api/internal/infra/postgres/scan_workflow_version_repository.go` |
| Run map | `GET /scan-runs/{id}/map` (`scans:read`, run guard): the run drawn on the workflow version it executes. Each step has a state (pending, waiting, running, succeeded, partial, failed, skipped, canceled), a reason (`waiting_for_sensor` or the error code and class), its chunks by state, findings, planned inputs and outputs by asset type. Each dependency carries the upstream output count. Output counts cover only the caller's data scope, no target or asset is named, and a platform job's message is masked. A fixed number of queries per call, none per step or per asset. Live: a run that changes (a step started, finished or queued, the run settled or canceled) sends `run.changed` on the websocket channel `run:{id}` (at most one a second per run; `scans:read` and a run the subscriber may read, finding scope for retests); the event carries no data, the page re-reads the gated endpoints, and polling stays as the fallback. Compared with the previous run: each step's outputs carry `previous`, `added` and `gone` against the latest completed or partial run of the same scan (`previous_run_id`), in the caller's data scope; the page warns about a finished step that produced no asset and no finding. `GET /scan-runs/{id}/outputs?step_key=` (`scans:read`) lists up to 50 of a step's assets, new ones first, in the caller's data scope | `api/internal/app/scanrun/run_map.go`, `api/internal/infra/http/handler/scan_run_map.go` |
| Stage chaining | not yet (every step scans the seed targets) | RFC-046 §5.2 |
| Automations | in-process executor fed by callbacks; outbox planned (P2). Cancel skips open steps and the executor stops before its next step; finished runs and steps are never rewritten | `api/internal/app/workflow/` |
| `scan_sessions` | **removed** (migration 001148): table, `/api/v1/scan-sessions`, web hooks. CI coverage counts a daemon scan from a completed command's report | `api/internal/infra/postgres/ci_coverage_repository.go` |

## 3. Things that are deliberately not wired

- **Scope schedules** (`scan_schedules`, Scoping › Schedules) were inert by
  Scoping IA decision D10 and have been **removed**: the
  `/api/v1/scope/schedules` API, the service, the repository and the
  `total_schedules` / `enabled_schedules` fields of `GET /scope/stats` are
  gone, and migration 001069 drops `scan_schedules`. Schedules belong to the
  Scan; do not reintroduce a second scheduler.
- **Interactsh** is off on the sensor unless the sensor-local policy and the
  job both allow it (RFC-040, RFC-046 D6).
- **Adaptive chunk sizing** is deferred (RFC-046 D9, RFC-030 Phase 2).
- **Automations refuse what they cannot run.** The schedule and finding_age
  triggers and the assign_team, update_priority and run_script actions
  (no sandbox for a tenant script) are refused on create, graph save, node
  edit and activation with 400 `UNSUPPORTED_WORKFLOW_FEATURE`; stored ones
  stay readable and flagged. A graph save is also refused, before anything
  is written, when the graph has a cycle (`WORKFLOW_GRAPH_CYCLE`), a node no
  trigger reaches (`WORKFLOW_GRAPH_UNREACHABLE`), an edge into a trigger or
  a condition edge without a yes/no handle (`WORKFLOW_GRAPH_EDGE`). Adding
  one edge checks the same except reachability; activation checks
  reachability too. The canvas refuses the same connections while dragging.

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
7. A run executes the workflow version it started with.
