# RFC-046 appendix A — status audit of the scans research (2026-10-03)

Companion to [RFC-046](RFC-046-scans-redesign.md). Every row below was
checked in code on `origin/develop` at `7a0c6c5f` (2026-10-03), with sdk-go
`main` at `638c07e` and sensor `main` at `804c008`. PR titles were not taken
on trust: each "fixed" row cites the line that does it. Paths are relative
to the monorepo root unless they name `sdk-go:` or `sensor:`.

Status values: **fixed** (the defect cannot happen on develop), **partly**
(the main path is fixed and a named gap remains), **open** (not started or
not effective).

## A.1 The worst bugs from the 2026-10-02 research

| # | Bug | Status | Evidence | Remaining work |
|---|---|---|---|---|
| 1 | Auto-resolve only for git repositories (`ingest/types.go:118`, `finding_repository.go:3440` joins `repository_branches`) | **partly** | The repository path is unchanged (`api/internal/app/ingest/types.go:135-141` `ShouldAutoResolve` needs full coverage **and** a default-branch scan; `api/internal/infra/postgres/finding_repository.go:3274-3284` joins `repository_branches ... is_default`). A second, coverage-scoped path for every other asset type now exists: `api/internal/app/ingest/coverage_autoresolve.go` (command completed with exit 0, every report completed with nothing rejected or quarantined, full coverage, one tool the sensor declared; resolves only findings on `touched_asset_ids` last seen by the same tool and scan profile; blinding guard; audit entry). It ships in **dry-run** (`api/internal/config/config.go:1192` `INGEST_COVERAGE_AUTO_RESOLVE=dry_run`). | Review two weeks of dry-run audit entries, then switch to `enforce` (D1). The coverage query keys on `tool_name`, not `last_seen_tool` (`finding_coverage_autoresolve.go:114,128-133`); align with RFC-043 sightings. v1-ingested findings never age out. |
| 2 | Every workflow step fails: payload has `preferred_tool`, no `scanner`; no output chaining | **partly** | `scanner` is set: `api/internal/app/scan/trigger.go:568` and `api/internal/app/pipeline/run.go:1105` (`payload["scanner"] = step.Tool`); sdk-go reads it (`sdk-go:pkg/core/command_poller.go:87`). No chaining: every step takes `run.Context["targets"]` (`trigger.go:575`, `run.go:1110`); `step_runs.output` is written (`run.go:588`) and never read. | Stage chaining through the inventory (RFC-046 §5, P2). Until then multi-step presets run every tool on the seed targets. |
| 3 | The web Runs tab reads the empty `scan_sessions` | **fixed** (UI) / **open** (table) | The scan detail page uses `useScanRuns` → `GET /scans/{id}/runs` (pipeline runs) (`web/src/app/(dashboard)/(discovery)/scans/[id]/page.tsx:105-114`; `web/src/features/scans/components/scan-runs-tab.tsx:33,97`). The only `scan_sessions` writer is `POST /api/v1/agent/scans` (`api/internal/infra/http/routes/scanning.go:230`, `api/internal/app/scan/session.go:94`); neither sdk-go nor the sensor calls it. | Retire `scan_sessions` (D2): CI runs become `trigger=ci` runs; delete `useScanSessions` and `ScanSessionDetailSheet` (no consumers). |
| 4 | Mock workflows | **partly** | Lists and runs are real (`web/src/app/(dashboard)/(mobilization)/workflows/page.tsx:441,444`). The builder still seeds a hardcoded demo graph (`page.tsx:196-236`) and shows it for any workflow with 0 nodes and on New/Clear/Reset (`:322-323, 706, 1084, 1096`). `web/src/features/scans/lib/mock-data.ts` is exported and unused. | Empty canvas for an empty workflow; delete the mock file. Folded into the Automations rename (D2). |
| 5 | Scanner hardcoded to nuclei | **partly** | New, Edit and Quick scan use the tool registry (`web/src/features/scans/components/scanner-select.tsx`). `scan-assets-dialog.tsx:77` still starts at `'nuclei'` with a fixed nuclei/nmap/subfinder/httpx list (`:208-211`); it is used by `attack-surface/external/page.tsx:763`, and no sensor ships nmap. | Switch `ScanAssetsDialog` to `ScannerSelect`. |
| 6 | Edit overwrites | **partly** | The API is patch-style (`api/internal/app/scan/crud.go:641-770`) and the web form no longer resets the scanner (`web/src/features/scans/lib/scan-form.ts:141-175`). New defect: the Edit wizard has a Targets step but `formDataToUpdateRequest` sends no `targets`/`asset_group_ids` and `UpdateScanInput` has no such fields, so target edits are dropped silently. A description cannot be cleared (`crud.go:650`). Workflow graph save deletes nodes and edges before `ValidateGraph`, outside a transaction (`api/internal/app/workflow/service.go:342-392`). | Add targets and groups to the update API (through the target gate); validate-then-replace the workflow graph in one transaction. |
| 7 | Cancel and timeout never reach the sensor | **partly** | Cancel: `CancelRun` cancels the run's commands (`api/internal/app/pipeline/run.go:1015-1048`, `api/internal/infra/postgres/command_repository.go:1458-1468`); the heartbeat returns `cancel_command_ids` for anything the sensor runs that it no longer holds (`api/internal/infra/postgres/command_lease.go:64-90`; v2 `sensor_control_v2_handler.go:204-205`, v1 `ingest_handler.go:948-949`; test `routes/sensor_cancel_signal_db_test.go`); sdk-go cancels the job context (`sdk-go:pkg/core/doorbell.go:318-319`, `command_poller.go:509-519`). Timeout: the payload carries `timeout_seconds` (`run.go:1099`), enforced by sdk-go with `context.WithTimeout`, capped at 24 h and by the local policy (`command_poller.go:1313-1323`). | (a) The cancel hook is wired only with the doorbell (`sdk-go:pkg/sensorkit/kit.go:652,856`): a sensor run with `-disable-doorbell` ignores cancels. (b) Latency is one heartbeat (default 60 s). (c) Automation-run cancel only updates the row (`api/internal/app/workflow/service.go:756`). |
| 8 | CIDR exclusions don't match | **fixed** (matcher) / **partly** (coverage of paths) | `api/pkg/domain/scope/value_objects.go:498-507,543` parses CIDR, ranges and single IPs with `netip` and tests overlap; URL and host:port forms are normalised (`api/internal/app/scope/service.go:1238`). Applied at scan trigger (`api/internal/app/scan/targets.go:150`), `POST /commands` (`command_gate.go:53,178`) and `/scope/check`. | Pipeline runs, the coverage dispatcher, CT monitoring and ingest-created assets do not apply exclusions on develop. Open PR #905 adds a dispatch gate for those paths; RFC-042 §6.11 makes it the single `scope.Gate`. RFC-046 reuses that gate. |
| 9 | Interactsh on by default | **fixed** | `sensor:internal/scanners/nuclei/scanner.go:76-88,551-555,649-657` (`-ni` unless explicitly enabled); sdk-go opts in only when the payload has `allow_interactsh` **and** the local policy allows it (`sdk-go:pkg/core/command_poller.go:1251-1255`); pipeline steps refuse the setting (`api/pkg/domain/pipeline/step_settings.go:97-98`); built-in sensor config `allow_interactsh: false` (`api/internal/app/sensor/config_templates_builtin.go:640`). | None. A tenant-server opt-in (D6) is a later feature. |
| 10 | Weekly without a day ran every 8 days | **fixed** | `api/pkg/domain/scan/entity.go:361-377` (`nextAtWeekday` uses today's slot or +7 days); weekly now requires a day (`entity.go:233-236`). | Scans saved before the rule may still have no day; the scheduler warns at startup about inert schedules (`api/internal/app/scan/scheduler.go:112-130`). |
| 11 | Cron ignored unless type is `crontab` | **fixed** | Non-crontab types clear the cron string (`entity.go:259-263`); invalid cron is rejected with the scheduler's own parser (`:253-254,357`) and yields no next run instead of "every 24 h" (`:326-329`). | Replaced by rrule (D11). |
| 12 | Scheduler advisory lock on different pooled connections | **fixed** | The lock is gone; each occurrence is claimed by a compare-and-set on `next_run_at` (`api/internal/infra/postgres/scan_repository.go:624-648` `ClaimScheduledRun`, called from `scheduler.go:188-197`). | No `scheduled_for` on runs and no `UNIQUE(scan_id, scheduled_for)`: a run cannot be tied to the occurrence it served, which rollover (D5) and audit need. Two session advisory locks remain elsewhere (`easm_dns_repository.go:170`, `ct_monitor_state_repository.go:104`). |
| 13 | Run counters double-counted ("87%" next to 4 failures) | **partly** | Backend: each run is counted once (`RecordRun` only through the guarded terminal transition, `scan_repository.go:436-461`; reapers only touch open runs, `pipeline_run_repository.go:556-566,635-645`). Web: two formulas — list uses succeeded/(succeeded+failed) (`web/src/features/scans/lib/format.ts:28-35`), detail and sheet use succeeded/`total_runs`, which includes canceled runs (`web/src/features/scans/lib/run-display.ts:39-45`, `scan-config-detail-sheet.tsx:214-219`); no runs shows 0 % in the "bad" colour. | One shared formula (succeeded / settled runs, canceled excluded, "n/a" with none), and `partial` counted on its own. |
| 14 | No `partial` state | **open** | `pipeline_runs` CHECK (`api/migrations/000018_pipelines.up.sql:83`) and the Go enum (`api/pkg/domain/pipeline/run.go:13-20`) have no `partial`. A batched step with one failed batch fails the whole run (`api/internal/app/pipeline/run.go:577-584`, `checkStepBatches`); the reaper ends runs as `timeout` with nothing kept (`pipeline_run_repository.go:509-573`). | P1.2/P1.3 (§9). |
| 15 | Non-retryable errors retried ×4 | **fixed** | `api/pkg/domain/pipeline/failure.go:10-72` (`SCANNER_NOT_FOUND`, `TARGET_REFUSED`, `NO_TARGETS`, `NO_SENSOR` never retried); run-level retry excludes them and caps `timeout` at 2 (`pipeline_run_repository.go:683-698`), backoff `retry_backoff_seconds × 2^attempt`. | Classification matches the sensor's free text (typed error codes come with RFC-029 v2 results). Step-level retry is dead code: `StepRun.CanRetry` requires status `failed` (`api/pkg/domain/pipeline/step_run.go:189-191`) but `failStep` is reached with a running step, so only run-level retry happens. |
| 16 | No EASM tools on sensors | **mostly fixed** | The sensor ships subfinder, dnsx, naabu, httpx and katana (`sensor:internal/recon/*`, `sensor:recon_tools.go:10-27`, `main.go:1179-1182`) in the `full`/`platform` image (`sensor:Dockerfile:347`); presets trimmed to them (`api/migrations/000270_recon_tools_shipped_presets.up.sql`). | No amass, tlsx, alterx or screenshot tool; not in the CI image; no discovery loop dispatches them (needs chaining, item 2). |

## A.2 Other defects found while auditing

| Defect | Evidence | Fix |
|---|---|---|
| A finished **step** run could be rewritten | `StepRunRepository.Update/UpdateStatus/Complete` filtered on `id` only (`pipeline_run_repository.go:1322-1420`); a duplicate result recounted findings, a late failure flipped a completed step and failed the run, a stale copy re-queued a canceled step | P1.1 (this RFC's first PR) |
| `POST /commands/{id}/cancel` needs only `commands:write` | `api/internal/infra/http/routes/scanning.go:50` | Decide with D12 (a scan's command is stopped through the run) |
| Scope schedules "Run now" marks running and dispatches nothing | `api/internal/app/scope/service.go:910-934`; `ListDueSchedules` (`:853`) has no caller | Deliberately inert (Scoping IA D10): do not wire; hide "Run now". Since removed: API and code deleted, migration 001069 drops `scan_schedules` |
| Automations can loop | `scan_completed` → `trigger_scan` → `DispatchScanCompleted` with no origin check (`api/internal/app/workflow/event_dispatcher_discovery.go:190-240`) | B5 |
| `command_queue_size` gauge never set | `api/internal/metrics/metrics.go:73-104` | P1 observability |

## A.3 Decisions D1–D13

| # | Decision | Status | Evidence | Remaining work |
|---|---|---|---|---|
| D1 | Coverage-scoped auto-resolve; 2-week dry-run first; never from partial or failed runs | **partly** | Coverage path and dry-run default exist (A.1 #1); failed, canceled, expired, partial-coverage and non-zero-exit commands never qualify (`coverage_autoresolve.go:10-11,72-77`) | Run the dry-run window, review, switch to `enforce`; once `partial` exists, assert in a test that a partial run's failed tasks never resolve |
| D2 | Scan → Run → Task; retire `scan_sessions` (CI = `trigger=ci`); Workflows → Automations | **open** | Runs are `pipeline_runs`, tasks are `step_runs` + `commands`; `scan_sessions` still exists; sidebar says "Workflows" (`web/src/config/sidebar-data.ts:479-480`) | P1.4 (read model), P2 (rename, compat views), P4 (Automations) |
| D3 | Declarative engine spec over a validated stage catalogue; builder edits the spec | **open** | Templates are DB rows (`pipeline_templates`, `pipeline_steps`); profiles feed only the quality gate (`trigger.go:224`) | P2 |
| D4 | Skip overlapping scheduled runs | **fixed** | `scheduler.go:207-217` (`SkipIfRunning`, metric `skipped_overlap`, audit entry); `trigger.go:75-81` | Make the overlap check and the insert one transaction (P1.6) |
| D5 | Deadline → `partial`; unfinished targets roll over | **open** | No `partial` (A.1 #14); deadline exists as `timeout_seconds` + 24 h ceiling | P1.2, P1.3 |
| D6 | Interactsh off by default | **fixed** | A.1 #9 | — |
| D7 | Never retry permanent classes; retry lease expiry and timeout ×2 with backoff | **fixed** | A.1 #15; lease expiry → `COMMAND_EXHAUSTED` retryable | Typed error codes; remove or fix the dead step-level retry |
| D8 | Abort unclaimed runs after 4 h (scheduled) / 1 h (interactive) | **fixed** | `api/internal/infra/controller/scan_timeout.go:68-69`; `AbortUnclaimedRuns` (`pipeline_run_repository.go:586-664`) | — |
| D9 | Defer adaptive chunks | **honoured** | RFC-030 Phase 2 not started | — |
| D10 | Quick scan is ad hoc + "Save as scan" | **fixed** | `api/migrations/000271_scans_ad_hoc.up.sql`; `api/internal/app/scan/run.go:225,294-308`; `POST /scans/{id}/save`; `quick-scan-dialog.tsx:68,153` | Offer Save from a run later; clean up unsaved ad-hoc rows (retention) |
| D11 | rrule + timezone schedules | **partly** | Timezone works (`entity.go:269,306-311`); no rrule | P1.5 |
| D12 | Cancel needs `scans:write` | **fixed** for runs | `scanning.go:426-430` `RequireAll(PipelinesWrite, ScansWrite)` | Command cancel route (A.2) |
| D13 | Recon extras ship with EASM P3–P4 | **not due** | — | Tracked by RFC-036 |

## A.4 Backend decisions B1–B12

| # | Decision | Status | Evidence | Remaining work |
|---|---|---|---|---|
| B1 | Postgres only: claim-N `SKIP LOCKED`, `domain_events` outbox, `controller_leases` | **partly** | Leases with epoch fencing exist (`api/pkg/domain/command/lease.go:80-130`, `ClaimForSensor` `command_repository.go:373-385`, requeue with `SKIP LOCKED` `command_lease.go:138`). The tenant poll is a plain `SELECT ... LIMIT` and claim is one id at a time (`command_repository.go:128-158`); no `domain_events`, no `controller_leases` | P1.7 (claim-N), P1.8 (`controller_leases`), P2 (outbox) |
| B2 | Two engines (Scans data plane, Automations control plane) on one outbox | **open** | Automations are fed by in-process callbacks (`api/cmd/server/services.go:1686-1918`) and run in goroutines (`api/internal/app/workflow/executor.go:702`) | P2 outbox, P4 Automations |
| B3 | Durable automation steps in-house after a one-week DBOS spike | **open** | `workflow_runs`/`workflow_node_runs` exist (`api/migrations/000040_workflows.up.sql:88,120`), execution is in memory with no resume | P4 |
| B4 | One API replica until HA lands | **done outside this repo** | helm-charts#21 (chart 0.10.2) sets one replica; this repo has no chart (`deploy/allinone` only) | Lift after P1.7–P1.9 with two-replica race tests |
| B5 | Loop guards, service identity, approvals | **open** | No depth/origin guard; actor is the string `workflow:<id>` (`action_handlers.go:189,409,454`) | P4 |
| B6 | Retire the 6 facade presets | **partly** | `000270` trimmed them and deactivated 2; 4 remain facades (no chaining) | P2 with the engine migration |
| B7 | Allow-list scope for EASM engines | **open** | Only the attribution gate for group members (`api/internal/app/scan/targets.go:157-167`) | P3 (with RFC-036 and RFC-042 `scope.Gate`) |
| B8 | 200k targets per run cap; minimum schedule interval 15 min | **open** | Caps today: 10,000 resolved targets (`targets.go:19,193`), 1,000 zone jobs (`zones.go:41`), 1,000 direct targets (`crud.go:232`); `* * * * *` accepted | Minimum interval in P1.5; 200k cap with the RFC-030 Phase 2 planner |
| B9 | Drop `tenant_id` from metric labels | **open** | `tenant_id` on most series (`api/internal/metrics/metrics.go:17-125`, `security_defenses.go:53-105`, `ctem_metrics.go:69-111`) | P1.9 |
| B10 | Retire asynq/Redis for jobs | **open** | `go.mod:12`; `api/internal/infra/jobs/*`; started in `cmd/server/workers.go:128` | P4 |
| B11 | Retention: changes 13 months, screenshots 30 days, ingest reports 90 days, v1 payloads cleared | **open** | Retention exists only for audit, notifications, heartbeats, sensor events and reviewed quarantine | P3 |
| B12 | Non-repository auto-resolve keyed by run + coverage, not report id | **partly** | Coverage path keys on the command and its reports (A.1 #1) | Key on run + task coverage when `partial` and rollover land |

## A.5 Plan items already on develop (P0)

| PR | Claim | Verified |
|---|---|---|
| #820 | A finished run stays finished | Run writes guarded (`pipeline_run_repository.go:168-173,206,353-369`); **step runs were not** → P1.1 |
| #824 | Dispatch only verified tools | `command_repository.go:299-319` (`sensorDispatchTools`), test `routes/sensor_dispatch_verified_tools_db_test.go` |
| #830 | Scheduler claims each occurrence once | A.1 #12 |
| #833 | Retries by failure class | A.1 #15 |
| #837 | Workflow DAG start | `trigger.go:429-461`, `run.go:213-218` |
| #847 | Report and coverage schedulers claim once | `report_scheduler.go:89-118` (`ClaimDue`); `scan_coverage_repository.go:202-251` |
| #850 | Conditional expiration checker | `ExpireIfUnchanged` expires a command only if it is still as read (`api/internal/infra/postgres/command_repository.go:1094-1100`) |
| #854 | Legacy health checker off | `WORKER_HEALTH_CHECK_ENABLED` default false (`api/internal/config/config.go:697`) |
| #845 | Audit chain cannot fork | `pg_advisory_xact_lock` + tail read + insert in one transaction (`audit_repository.go:662-698`) |
| #834 | Quick scans (D10) | D10 above |
