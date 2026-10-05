# RFC-046 — Scans redesign: Scan → Run → Task, engines, schedules and automations

> Status: **Accepted.** Product decisions D1–D13 approved by the owner on
> 2026-10-02; backend decisions B1–B12 approved on 2026-10-03. P0 shipped
> (§2.3); P1 in progress (§16): merged P1.1 (#940), P1.2 `partial` (#946)
> and the P1.5 occurrence key `UNIQUE(scan_id, scheduled_for)` (#949; the
> rrule part of P1.5 is open); P1.3 deadline → `partial` + rollover
> (migration 000674; trigger type `rollover` waits for P1.4).
> P2 chaining (research/27 P0, owner decisions G1–G12, 2026-10-05): the stage
> catalogue with typed inputs and outputs (`pkg/domain/stage`, migration
> 001020 `tools.output_types`, `GET /api/v1/scans/stages`) and the one
> planner (capability → tool at plan time, one payload builder and one step
> dispatcher; fixes F1 and F2) are in review; the hop router with the per-hop
> gate, report output-type binding and run-drawer stage lanes follow. State:
> [architecture/scan-stages.md](../architecture/scan-stages.md).
> Scope: api + web, with sdk-go and sensor changes where a phase says so.
> Builds on and does not duplicate:
> [RFC-030](RFC-030-scan-work-distribution.md) (pull, chunks, leases, fair
> share — the dispatch core this RFC keeps),
> [RFC-023](RFC-023-scan-zones-and-scanners.md) (zones),
> [RFC-033](RFC-033-sensor-manifest.md) / [RFC-035](RFC-035-sensor-control-plane-under-load.md)
> (what a sensor can run, heartbeats),
> [RFC-039](RFC-039-continuous-retest.md) (retests are runs),
> [RFC-040](RFC-040-platform-sensor-mutual-distrust.md) (signed jobs, local
> policy), [RFC-042](RFC-042-asset-inventory-v2.md) (the one target gate,
> dynamic groups as targets) and [RFC-036](RFC-036-easm.md) (EASM engines).
>
> Appendix A, [status audit](RFC-046-appendix-status-audit.md): every bug,
> decision and P0 item checked in code on `develop` 2026-10-03.
> Current-state and target architecture:
> [architecture/scan-lifecycle.md](../architecture/scan-lifecycle.md).
>
> Owner (2026-10-03): "earlier there was the research on /scans; now start
> implementing it well."

## 1. Answer in short

Scanning has one owner of "what should be scanned, how, and was it covered":
the **Scan**. A scan is a definition (targets, engine, schedule, scope); each
time it fires it creates a **Run**; a run is cut into **Tasks** (RFC-030
chunks: one tool, a slice of targets, one sensor attempt at a time). Runs end
`completed`, `partial`, `failed`, `canceled` or `timeout`, never "completed"
with work silently missing. A run that hits its deadline ends `partial` and its
unfinished targets roll over to the next window. Auto-resolve for every asset
type is keyed by **what a task actually covered**, never by a whole run that
only partly finished.

How a scan runs is an **engine spec**: a small declarative document over a
validated **stage catalogue** (reNgine-style), which the builder edits. Stages
chain through the inventory: a stage's output assets become the next stage's
targets after passing the one target gate (RFC-042 §6.11).

Schedules are rrule + timezone, claimed once per occurrence
(`UNIQUE(scan_id, scheduled_for)`), skip overlaps, and are at least 15 minutes
apart.

Everything that reacts to events ("when a critical finding appears, open a
ticket") is an **Automation**, a separate control-plane engine that shares a
transactional `domain_events` outbox with the scan engine. Automations have
loop guards, run as a service identity with the creator's permission snapshot,
and need approval for intrusive or bulk actions.

Everything stays on Postgres: claim-N with `FOR UPDATE SKIP LOCKED`,
`controller_leases` for non-idempotent sweeps, the outbox for events. No
broker until more than 1,000 sensors.

## 2. Problem

### 2.1 Live numbers (2026-10-02)

- 40 runs ever on the live deployment, **4 completed (10 %)**.
- 10 scans, all single-tool; all 40 runs on the system Quick Scan template.
- 6 multi-step pipeline presets with 0 runs (they used tools no sensor
  shipped); 1 automation ("workflow"), 0 runs.
- The scan list showed "87 %" success next to 4 failed runs.

### 2.2 Root cause

Five overlapping "scan" concepts (scans, pipeline templates + runs,
`scan_sessions`, scan profiles, workflows) and two step dispatchers, with
nobody owning **definition → coverage**:

| Concept | Table(s) | What it really is |
|---|---|---|
| Scan | `scans` | The definition (and, for quick scans, an ad-hoc row) |
| Pipeline template / run | `pipeline_templates`, `pipeline_steps`, `pipeline_runs`, `step_runs` | The real execution record |
| Scan session | `scan_sessions` | Written only by `POST /agent/scans`, which no client calls |
| Scan profile | `scan_profiles` | Only its quality gate is used |
| Workflow | `workflows`, `workflow_*` | Event automation, in-memory goroutines |
| Scope schedule | `scan_schedules` | Inert by decision (§6.6) |

33 verified bugs followed from that split (research 2026-10-02). The
**dispatch core is sound**: pull, compare-and-set claim, epoch-fenced leases
and server-side capacity (RFC-030 Phase 0/1) were proven with two replicas
(106 claims, 0 conflicts). What broke is everything around it: what a run
means, when it is done, what it covered, and who reacts to it.

### 2.3 What P0 already fixed

P0 (correctness, no model change) is merged: #820 a finished run stays
finished, #824 dispatch only verified tools, #830 the scheduler claims each
occurrence once, #833 retries by failure class, #837 workflow DAG start, #847
report and coverage schedulers claim once, #850 conditional expiration, #854
legacy health checker off, #845 the audit chain cannot fork, #834 quick scans
(D10). Appendix A verifies each in code and lists what each left open; the
largest leftovers are no `partial` state, step runs that could be rewritten
after finishing, no occurrence key on runs, the auto-resolve dry-run still to
be switched on, and no chaining between stages.

## 3. Decisions (approved)

### 3.1 Product decisions D1–D13 (owner, 2026-10-02)

| # | Decision |
|---|---|
| D1 | Auto-resolve for non-repository findings is **coverage-scoped**: a finding resolves only when a task fully covered its asset with its tool and did not report it. Two weeks of **dry-run** first. Never from partial or failed coverage. |
| D2 | One model: **Scan → Run → Task**. Retire `scan_sessions` (CI runs become runs with `trigger=ci`). Rename the event automation "Workflows" to **"Automations"**. |
| D3 | A **reNgine-style declarative engine spec** over a validated **stage catalogue**; the builder edits the spec. |
| D4 | **Skip** a scheduled occurrence while the scan's previous run is still active. |
| D5 | A run that reaches its **deadline ends `partial`**; unfinished targets **roll over** to the next window. |
| D6 | **Interactsh off by default**: only for tier T2 engines or a tenant's own interactsh server. |
| D7 | Never retry scanner-not-found, target-refused, no-targets, no-sensor; retry lease expiry and timeout **×2 with backoff**. |
| D8 | Abort runs nobody claimed after **4 h (scheduled)** or **1 h (interactive)**. |
| D9 | Defer adaptive chunk sizing (RFC-030 Phase 2). |
| D10 | Quick scan is **ad hoc**, with "Save as scan". |
| D11 | Schedules are **rrule + timezone**. |
| D12 | Cancelling a run needs **`scans:write`**. |
| D13 | reNgine extras (screenshots, OSINT, dorks, …) ship with EASM P3–P4. |

### 3.2 Backend decisions B1–B12 (owner, 2026-10-03)

| # | Decision |
|---|---|
| B1 | **Postgres only** for the queue, events and storage: claim-N with `FOR UPDATE SKIP LOCKED`, a `domain_events` transactional outbox, `controller_leases`. Revisit above 1,000 sensors or 1,000 claims/s. |
| B2 | **Two engines** — Scans (data plane: untrusted remote sensors pull work) and Automations (control plane: event-driven) — on one shared outbox, scheduler, claim mechanism and audit trail. |
| B3 | Durable automation steps built **in-house**, after a one-week DBOS Go spike (adopt DBOS only if it runs on our pgx pool, keeps our tenant context and adds no infrastructure). |
| B4 | **One API replica** until the HA items of P1 land (enforced by helm-charts#21). |
| B5 | Automation-caused events do not trigger automations by default; chain depth ≤ 3; actions run as a **service identity** with the creator's **permission snapshot**; a fixed list of actions always needs **approval**. |
| B6 | Retire the 6 facade presets; the 1 tenant template and the 1 workflow become drafts; `/pipelines` and `/workflows` stay read-only and deprecated for one release. |
| B7 | **Allow-list scope** (in-scope assets and verified roots) enforced at trigger and at every stage for EASM engines, not only exclusions. |
| B8 | At most **200,000 targets per run**; minimum schedule interval **15 minutes**. |
| B9 | No `tenant_id` in metric labels; per-tenant views come from logs and traces. |
| B10 | Retire asynq and Redis for jobs (P4). |
| B11 | Retention: changes 13 months, screenshots 30 days, ingest reports 90 days, v1 job payloads cleared on completion. |
| B12 | Non-repository auto-resolve keyed by **run + coverage**, not by report id (complements D1). |
| — | Plus OpenTelemetry: traces with `traceparent` through the command payload, queue metrics. |

### 3.3 Interpretation recorded with this RFC

- **"Never from partial runs" (D1/B12)** is applied per task: the unit of
  coverage is a task. A task that completed with full coverage of its targets
  may resolve findings on exactly those targets even when another task of the
  same run failed; a failed, canceled, expired, timed-out or partially covered
  task never resolves anything. This is what `coverage_autoresolve.go` does
  today and is the only reading under which a 200,000-target run with one
  failed chunk still closes anything. If the owner prefers the strict reading
  (no resolution at all from a run that ends `partial`), resolution moves from
  task completion to run settlement; the data needed for both is the same.
- **Scope schedules** (`scan_schedules`, Scoping › Schedules) are
  **deliberately inert** by Scoping IA decision D10 and **must not be wired**
  to the scheduler or the dispatcher. Scheduling lives on the Scan only. The
  "Run now" button that only marks them running is hidden.

## 4. Target model

### 4.1 Entities

```
Scan (definition)                      Run (one firing)                     Task (one unit of work)
─────────────────                      ────────────────                     ───────────────────────
id, tenant_id, name                    id, scan_id, tenant_id               id, run_id, stage_key
engine_spec (version, stages)          trigger: schedule|manual|api|ci|     tool, zone_id
targets: selection (RFC-042)                    retest|automation|rollover   targets[] (chunk)
schedule: rrule + tz, window, jitter   scheduled_for (occurrence)           attempt, max_attempts
deadline, overlap=skip                 status (§4.2), deadline_at           lease (RFC-030), sensor_id
scope: allow-list (EASM), tier         progress {targets done/failed/…}     status, error_code
status: active|paused|disabled         coverage summary, unfinished[]       coverage {full|partial}
ad_hoc (quick scan, D10)               actor (user | service identity)      report ids (RFC-026)
```

Mapping onto today's tables (no big-bang rename; §8):

| Model | Today | Change |
|---|---|---|
| Scan | `scans` | `engine_spec` (P2), `rrule`/`tz` (P1), allow-list scope (P3) |
| Run | `pipeline_runs` | `scheduled_for` + `UNIQUE(scan_id, scheduled_for)`, `partial`, `trigger=ci/retest/automation/rollover`, `deadline_at`, unfinished targets (P1) |
| Task | `step_runs` (stage) + `commands` (attempt) | RFC-030 `scan_chunks` when adaptive chunks land (D9 defers); until then a task = one command of a step |
| — | `scan_sessions` | retired (CI → runs with `trigger=ci`) |
| Stage catalogue | `pipeline_steps` + `tools` | catalogue rows (P2) |

### 4.2 Run states

```
            ┌──────────── cancel (scans:write) ───────────────┐
            │                                                 ▼
 pending ──claim──▶ running ──all tasks done──▶ completed   canceled
    │                  │ ├──some tasks done, some failed──▶ partial
    │                  │ ├──deadline, some done──────────▶ partial (unfinished → rollover)
    │                  │ ├──deadline, none done──────────▶ timeout
    │                  │ └──all tasks failed─────────────▶ failed
    └── nobody claimed in 4 h / 1 h (D8) ───────────────▶ failed (NO_SENSOR)
```

- Terminal states: `completed`, `partial`, `failed`, `canceled`, `timeout`.
  A terminal run never moves again (#820); a terminal step run never moves
  again (P1.1).
- `partial` means "results kept, coverage incomplete". It is not retried as a
  whole (RFC-030 §9 decision 4: "Retry failed" re-runs only the failed
  tasks); its unfinished targets roll over (§6.3).
- Counters on the scan: `total_runs`, `successful_runs`, `failed_runs` and a
  new `partial_runs`; the success rate is
  `successful / (successful + partial + failed)`, canceled excluded, "n/a"
  with no settled run — one formula for every page.
- Step runs gain `partial` too (a batched step where some batches failed).

### 4.3 Data-model changes and migrations

All additive; numbers are taken at merge time above the highest on develop and
every open PR (350+ in this cycle).

| Migration | Content | Phase |
|---|---|---|
| step/run `partial` | `pipeline_runs` and `step_runs` CHECKs gain `partial`; `scans.partial_runs INT NOT NULL DEFAULT 0` | P1.2 |
| occurrence key | `pipeline_runs.scheduled_for timestamptz NULL`; `CREATE UNIQUE INDEX ... ON pipeline_runs (scan_id, scheduled_for) WHERE scheduled_for IS NOT NULL` | P1.5 |
| run deadline + rollover | `pipeline_runs.deadline_at`, `pipeline_runs.unfinished_targets jsonb` (bounded; full list moves to `scan_run_targets` with RFC-030 Phase 2) | P1.3 |
| schedules | `scans.schedule_rrule text`, `scans.schedule_window interval`, `scans.schedule_jitter_seconds int`; existing daily/weekly/monthly/crontab converted to rrule by a backfill | P1.5 |
| trigger types | `chk_pipeline_runs_trigger_type` gains `ci`, `retest`, `automation`, `rollover` | P1.4 |
| `controller_leases` | `(name text PK, holder text, epoch bigint, expires_at timestamptz)` | P1.8 |
| `domain_events` | uuidv7 id, `tenant_id`, `type`, `subject`, `actor`, `causation_id`, `correlation_id`, `depth`, CloudEvents payload, `published_at`; partial index on unpublished | P2 |
| engines | `engine_specs (id, tenant_id NULL=system, name, version, spec jsonb, tier)`, `scans.engine_spec_id` | P2 |
| retire sessions | `scan_sessions` → read-only view over runs with `trigger=ci`, dropped one release later | P2 |

## 5. Engines: the spec and the stage catalogue (D3, P2)

An **engine** is a versioned, declarative document. The builder edits it; the
API validates it against the catalogue before saving; the run planner reads
it. It replaces pipeline templates and the facade presets (B6).

```yaml
engine: external-discovery
version: 3
tier: T1                      # ceiling for every stage (RFC-036 §6.3)
scope: allow_list             # EASM engines: only in-scope roots (B7)
stages:
  - key: subdomains
    uses: subfinder           # catalogue entry
    inputs: [domain]          # seed types accepted
  - key: resolve
    uses: dnsx
    after: [subdomains]
    inputs: [subdomain]       # chained through the inventory (§5.2)
  - key: ports
    uses: naabu
    after: [resolve]
    with: { top_ports: 100 }  # typed options only (RFC-038 schema)
  - key: http
    uses: httpx
    after: [ports]
  - key: vulns
    uses: nuclei
    after: [http]
    with: { severity: [high, critical], interactsh: false }
```

### 5.1 Stage catalogue

A catalogue entry is code-reviewed data, not tenant input:

| Field | Meaning |
|---|---|
| `uses` | Tool name; must be a tool a sensor declares in its RFC-033 manifest |
| `inputs` / `outputs` | Asset types consumed and produced (RFC-042 type registry) |
| `tier` | T0 passive, T1 light active, T2 intrusive (RFC-036 §6.3) |
| `options` | RFC-038 settings schema; typed values mapped to fixed flags, never free-form args |
| `cost` | RFC-030 cost prior (seconds per target) |
| `politeness` | Per-host concurrency and rate defaults (RFC-030 §5.6) |
| `max_fanout` | Cap on targets a stage may plan for its successors |

Validation on save: acyclic, every `uses` in the catalogue, `inputs` reachable
from the scan's target types or an earlier stage's `outputs`, every option
valid against the tool's schema, every stage `tier ≤` engine tier ≤ tenant
ceiling, `interactsh: true` only for T2 or with a tenant interactsh server
(D6). Unknown keys are refused.

### 5.2 Chaining through the inventory

A stage is planned only after **its predecessors' tasks finished and every
ingest report for them committed** (the outbox event that follows ingest
commit, not command completion — that ordering is today's race). The planner
reads the run's newly ingested assets of the stage's `inputs` types, passes
them through **the one target gate** (`scope.Gate`, RFC-042 §6.11 — this RFC
does not define its own), applies `max_fanout` and the run's 200k cap (B8),
and inserts the stage's tasks. Planning is exactly once per
`(run, stage)` (unique key + compare-and-set), so a duplicate event never
plans twice and a diamond graph never queues a stage twice.

### 5.3 Migration from templates

The 6 system presets are dropped (B6); the 1 tenant template and the 1 workflow
become drafts; single-tool scans become one-stage engines generated on the fly
(no row); `/pipelines` and `/workflows` stay read-only for one release.

## 6. Scheduling (D4, D5, D11, B8)

### 6.1 Occurrences

- A schedule is an **rrule (RFC 5545) + IANA timezone**, optional window
  (`BYHOUR` range during which new tasks may be cut) and jitter (0–10 min,
  stable per scan so daily scans do not all fire at 00:00).
- Minimum interval **15 minutes** (B8), checked on save by expanding the rrule
  over a horizon; `FREQ=MINUTELY` with `INTERVAL<15` is refused.
- The scheduler claims an occurrence by compare-and-set on `next_run_at`
  (today, #830) **and** inserts the run with `scheduled_for = occurrence`
  under `UNIQUE(scan_id, scheduled_for)`. The constraint is the hard
  guarantee: any path that tries to create a second run for the same
  occurrence (a second replica, a retried trigger) fails on insert.
- **Misfire grace**: an occurrence more than one interval late (API down) is
  skipped and recorded, not replayed in a burst.

### 6.2 Overlap

Overlap policy is **skip** (D4): an occurrence whose scan still has an active
run is recorded as skipped (metric, audit entry) and not queued. The check and
the insert move into one transaction that locks the scan row (P1.6), closing
the window where a manual trigger slips in between.

### 6.3 Deadlines, `partial` and rollover

- Every run gets `deadline_at = started_at + max(scan.timeout_seconds,
  planned estimate)` (RFC-030 §5.5; existing scans never get a shorter limit),
  capped by the 24 h absolute ceiling.
- At the deadline the reaper settles the run: tasks still queued are dropped,
  leased tasks get a cancel signal (§8), the run ends **`partial`** if any task
  completed, otherwise `timeout`.
- The run records its **unfinished targets**. The next occurrence of the same
  scan plans them **first** (trigger `rollover` when nothing else is due),
  so a scan whose window is too short still covers everything over successive
  windows instead of rescanning the same head of the list.
- Ad-hoc and manual runs do not roll over (nothing is "next"); the run page
  offers "Scan the unfinished targets".

## 7. Retries and aborts (D7, D8)

| Failure class | Code(s) | Retry |
|---|---|---|
| Permanent | `SCANNER_NOT_FOUND`, `TARGET_REFUSED`, `NO_TARGETS`, `NO_SENSOR` | never |
| Lost work | lease expiry (`COMMAND_EXHAUSTED`), `timeout` | ×2, backoff `retry_backoff × 2^attempt` with jitter |
| Tool error | anything else | the scan's `max_retries` (default 0) |

- Retries are **per task** once tasks are chunks (RFC-030 §5.4: re-queue the
  chunk, split after failing on two sensors, poison after `max_attempts`);
  until then the run-level retry controller applies, and only to `failed` /
  `timeout` runs, never to `partial`.
- The dead step-level retry (`StepRun.CanRetry` requires `failed`, but a
  failure reaches it while the step is running) is removed in P1.2, so there
  is one retry path.
- Typed error codes replace message matching when v2 results carry them
  (RFC-029).
- Runs nobody claimed are aborted after 4 h / 1 h with `NO_SENSOR` (D8,
  shipped).

## 8. Cancel signals to sensors (D12)

Shipped: `POST /pipeline-runs/{id}/cancel` needs `pipelines:write` **and**
`scans:write`; it cancels the run's open commands; the next heartbeat returns
`cancel_command_ids` for any id the sensor runs but no longer holds; sdk-go
cancels the job's context (process-group kill); the reaper does the same at
the deadline. Also shipped: the cancel closes the run's open **step runs**
and commands in one statement (`CloseCanceledRun`), the commands lose their
lease so the expired-lease sweep never re-queues them (a sensor that was
offline is told to stop when it comes back and reports them), a sensor that
held a just-canceled command is asked to ring again within the busy interval
(5 s) instead of the idle one, and a second cancel succeeds without counting
the run again. Remaining (P1.10):

- sdk-go honours cancels without the doorbell (today a sensor started with
  `-disable-doorbell` runs canceled work to the end);
- `POST /commands/{id}/cancel` on a `scan` command needs `scans:write` too;
- ~~Automation-run cancel stops its pending steps, not just the row~~
  (shipped: the cancel skips the run's open steps, tenant-scoped; the
  executor stops before its next step; a finished run or step is never
  rewritten, so the executor finishing cannot overwrite the cancel);
- the cancel is audited with the actor and the run; latency ≤ one heartbeat
  (≤ 60 s) is documented, with the long-poll doorbell as the fast path.

## 9. Coverage-scoped auto-resolve (D1, B12)

Shipped in dry-run: `api/internal/app/ingest/coverage_autoresolve.go`. A
finding on asset A last seen by tool T under profile P resolves when a task of
tool T, profile P, covered A fully (exit 0, every report completed with
nothing rejected or quarantined, coverage `full`, the sensor declared T), and
did not report it. Pentest, manual, bug-bounty and red-team findings are never
auto-resolved. A blinding guard holds a resolution for review when a task
would close more than the configured ratio of an asset's findings.

Plan:

1. Dry-run for **two weeks** from the deploy that carries it; every would-be
   resolution is an audit entry (`ingest.coverage_auto_resolve.dry_run`).
2. Review: sample false positives by tool; publish the counts in the run's
   coverage summary.
3. ~~Switch `INGEST_COVERAGE_AUTO_RESOLVE=enforce` after the review window
   (~2026-10-16).~~ **Postponed (owner decision D-22 / O1, 2026-10-04,
   research 18).** The mode stays `dry_run`. This path proves coverage per
   tool, profile and asset, but not per check, port or authentication, so a
   template-pack update or a removed template would read as "fixed".
   Enforcement waits for the **closure evaluator** (research 18 P2: per-check
   coverage records, a detector-set digest, `metadata.execution`), and at
   minimum for an explicit `coverage_type` (absent is not full) and the nuclei
   exit-code fix. P2-4 (the owner reviews the evaluator's dry-run counts, then
   enforces per tenant) replaces this step. No code, config or schedule
   switches it; `INGEST_COVERAGE_AUTO_RESOLVE` defaults to `dry_run` and is
   unset on live.
4. Key on `last_seen_tool` (RFC-043 sightings later) instead of `tool_name`.
5. With `partial` (P1.2): a test proves a partial run's failed tasks never
   resolve and its completed tasks resolve only their own targets (§3.3).

## 10. Automations and the outbox (B2, B3, B5, P2/P4)

```
API transaction ──(state change + INSERT domain_events, same tx)──► domain_events
   relay (SKIP LOCKED, per tenant/subject order, idempotent consumers, replay)
     ├─► Notifications        ├─► Automations (durable runs/steps)
     ├─► WebSocket live view  ├─► Outbound webhooks / SIEM
     └─► Scan planner (stage chaining after ingest commit)
```

- **Outbox**: every domain change that others react to inserts its event in
  the same transaction (`finding.created`, `finding.status_changed`,
  `asset.discovered`, `run.settled`, `ingest.report.committed`, …). One
  naming scheme, CloudEvents envelope, `depth` and `causation_id` carried.
  LISTEN/NOTIFY is only a wake-up hint.
- **Automations** = trigger + CEL filter + steps, executed durably
  (`automation_runs`, `automation_steps` claimed with SKIP LOCKED, resumable
  after restart, waits and approvals). Today's in-process goroutine executor
  and direct callbacks are retired.
- **Loop guards (B5)**: events caused by an automation carry
  `origin=automation:<id>` and do not trigger automations unless the rule opts
  in; depth ≤ 3; per-rule cooldown per subject; a circuit breaker after three
  capped runs disables the rule and notifies its owner.
- **Identity (B5)**: actions run as the automation's service identity holding
  a snapshot of the creator's permissions, re-checked at execution (a creator
  who lost `scans:write` stops their automations from scanning).
- **Approvals (B5)**: always required, from someone other than the creator,
  for T2 scans, bulk changes over 50 findings, accept-risk, delete, and a
  webhook to a new domain.
- Declarative policies (assignment, suppression, priority override, SLA) stay
  policies on the ingest path; they do not become automations.

## 11. HA (B1, B4)

- **Claim-N**: the sensor poll becomes one statement that selects up to the
  sensor's free slots with `FOR UPDATE SKIP LOCKED`, applies the zone, tool,
  capability and pinning predicates (unchanged), orders by priority class
  (`verify > interactive > scheduled > background`, with ageing) and
  round-robin per run (RFC-030 §5.3), and sets the lease and epoch in the same
  `UPDATE ... RETURNING`. Fencing on every write is unchanged.
- **Politeness**: per-host in-flight limit and zone rate (RFC-030 §5.6).
- **`controller_leases`**: every sweep that is not idempotent (retention,
  EPSS refresh, report emails, coverage batches, CT polling, DNS checks)
  takes a named lease row with an epoch before working and renews it; the
  two remaining session advisory locks (`easm_dns_repository.go:170`,
  `ct_monitor_state_repository.go:104`) go.
- Rate limits move to Redis (they multiply per replica today).
- **B4 lifts** only after two-replica race tests (scheduler, claim, audit
  chain, every lease-holding sweep) pass in CI.

## 12. Observability, retention

- **Traces**: OpenTelemetry wired (it exists in code, unwired); `traceparent`
  in the command payload so a run's trace spans API → sensor → ingest.
- **Metrics** (no `tenant_id`, `sensor_id` or `pipeline_id` labels, B9): queue
  depth by class, claim latency, lease expiries, requeues, run outcomes by
  trigger and status, scheduler lag and skipped occurrences, stage planning
  latency. The 15 registered-but-never-written metrics are either written or
  deleted.
- **Logs**: one key, `run_id` (today `run_id` and `pipeline_run_id` both).
- **`GET /api/v1/runs/{id}/explain`** (`scans:read`, tenant-scoped): why a run
  is stuck — no capable online sensor in the zone, tasks blocked by
  politeness, outside the window, waiting on a predecessor's ingest, lease
  lost.
- **Retention (B11)** as lease-holding controllers: change observations 13
  months (monthly partitions), screenshots 30 days, ingest reports 90 days,
  v1 job payloads cleared on completion, unsaved ad-hoc scans 30 days, run and
  task rows kept 13 months (run summaries forever).

## 13. Security

### 13.1 Authorization on every action

| Action | Permission | Data scope |
|---|---|---|
| Read scans, runs, tasks, explain | `scans:read` | tenant; targets filtered by the user's asset data scope |
| Create/update scan, engine | `scans:write` (+ `scans:execute` to make it schedulable) | tenant; targets through the target gate preview |
| Trigger, retry, "scan the unfinished targets" | `scans:execute` | tenant |
| Cancel a run or a scan task | `scans:write` (D12) | tenant |
| T2 (intrusive) stage in an engine | `scans:write` + approval by a second person | tenant |
| Automation create/update | today `findings:workflows:write`; P2 renames it `automations:write` (the old name kept as an alias for one release) | tenant |
| Automation approval | a new `automations:approve` (P4), never the creator | tenant |

Every new route is registered with its permission in the route table, covered
by the route-permission test, and has a cross-tenant test (tenant B cannot
read, cancel, explain, retry or approve tenant A's object; ids of another
tenant return 404, not 403).

### 13.2 Tenant isolation

- Every query on runs, tasks, schedules, outbox rows and leases filters by
  `tenant_id` from the credential, never from the body; the getbyid lint
  covers new repository methods.
- Claim-N keeps the sensor's tenant (and zone) predicate inside the locked
  `SELECT`; a platform sensor claims only platform jobs, with the per-tenant
  cap of RFC-030 §5.7.
- The outbox relay delivers an event only to consumers of the event's tenant;
  automation steps execute with that tenant's context set before any query.
- Results are accepted only for a task the sensor holds under a live lease
  (epoch match) and only for that task's targets and tool (RFC-040 §5.3).

### 13.3 Scope: one gate, allow-list for EASM

- **One target gate.** Every path that turns a selection into work — trigger,
  stage chaining, rollover, retry, automation `trigger_scan`, quick scan,
  RFC-030 claim-time re-check — calls `scope.Gate` from RFC-042 §6.11
  (attribution, exclusions by name/alias/resolved IP/lineage, archived, tier
  ceiling, type compatibility, caps). This RFC adds call sites, not a gate.
- **Allow-list for EASM engines (B7)**: an engine with `scope: allow_list`
  only plans targets that are in-scope assets or under verified roots
  (RFC-036 §6.3); anything else discovered is ingested for review, never
  scanned.
- **Interactsh (D6)**: off by default on the sensor (`-ni`); an engine can ask
  for it only at T2 or with the tenant's own server, and the sensor-local
  policy must also allow it (RFC-040 §5.7).
- **Caps**: 200,000 targets per run, `max_fanout` per stage, 15-minute minimum
  interval, per-tenant budget (RFC-036 §6.7).

### 13.4 Signed jobs (RFC-040)

When RFC-040 P1 lands, every task is a DSSE envelope signed by the separate
signer over the exact bytes (tenant, sensor, task id, epoch, tool, targets,
options, expiry, nonce, `seq`); the sensor verifies it and checks it against
its local policy before running. This RFC's contribution: tasks are
declarative (tool + typed options + targets, no free-form args), so they are
signable; the signer's scope ledger receives the run's gated target set.

## 14. Threat model

| # | Threat | Vector | Control | Test |
|---|---|---|---|---|
| T1 | Cross-tenant read or cancel | Guessing run/task ids | Tenant from credential on every query; 404 for foreign ids | Cross-tenant route tests for every new route |
| T2 | Sensor claims another tenant's work | Forged poll, platform sensor | Tenant/zone predicate inside the locked claim; platform jobs only to platform sensors | Claim DB test with two tenants and a platform sensor |
| T3 | Zombie sensor writes after losing its lease | Late completion | Epoch fencing; `409 lease-lost`; late reports accepted once, scoped to their task | Fencing test (exists), late-report test |
| T4 | Scan storm / self-DoS | Automation loop, `* * * * *`, huge selection | Depth ≤ 3, origin guard, cooldown, breaker; 15-min minimum; 200k cap; budgets | Loop test (two rules stop at depth 3); rrule validator test; cap test |
| T5 | Scanning out of scope | Chained discovery outputs a third party's host | Target gate on every stage; allow-list for EASM engines; attribution | Chaining test with an unattributed output asset |
| T6 | Wrong auto-resolve | Partial coverage, failed task, blinded sensor | Coverage-scoped per task; dry-run; blinding guard; protected sources | Partial-run auto-resolve test; dry-run audit test |
| T7 | Privilege escalation via automation | Creator loses rights, rule keeps acting | Permission snapshot re-checked at execution; approvals for intrusive/bulk | Revoked-creator test |
| T8 | Duplicate effects with two replicas | Double-fired schedule, double sweep | `UNIQUE(scan_id, scheduled_for)`; `controller_leases`; outbox idempotency keys | Two-replica race tests |
| T9 | Out-of-band interaction leaks data | Interactsh to a public server | Off by default; T2 or tenant server only; sensor-local policy | Payload test (exists) |
| T10 | Tampered job | API or DB compromise | RFC-040 signed jobs + sensor-local policy | RFC-040 tests |
| T11 | Run history tampering | Rewriting a finished run or step | Terminal guards on runs (#820) and steps (P1.1); audit chain (#845) | DB tests |

## 15. Relation to other RFCs

- **RFC-030**: owns dispatch (chunks, leases, fair share, politeness, cancel
  protocol, progress/ETA). This RFC consumes it: a Task **is** an RFC-030
  chunk; `partial` and rollover are RFC-030 §5.5/§9.4 made concrete; D9 keeps
  adaptive chunks deferred.
- **RFC-042**: owns the target gate and dynamic groups as targets. Scans store
  a **selection** (static group, dynamic group, OQL, explicit ids) and resolve
  it through `scope.Gate` at trigger and at every stage. No second gate.
- **RFC-040**: owns job signing and the sensor-local policy. Tasks are
  declarative so they can be signed; scope ledger fed from the gated set.
- **RFC-036**: EASM engines are engines (external discovery preset in §5),
  P3 here = RFC-036's sensor pipeline; B7 allow-list = RFC-036 §6.3 seeds and
  verified roots.
- **RFC-039**: retests are runs with `trigger=retest` and the `verify`
  priority class.
- **RFC-023/033/035**: zones route tasks; the manifest says which tools a
  sensor runs; heartbeats carry lease renewal and cancel ids.

## 16. Phased plan

Each line is one small PR, in order, each with its acceptance tests. "DB test"
means a test against a migrated Postgres (skips without `DATABASE_URL`).

### P1 — run model, dispatch, HA prerequisites

| PR | Content | Acceptance tests |
|---|---|---|
| **P1.1** | A finished **step run** stays finished: `StepRunRepository.Update/UpdateStatus/Complete` guarded on non-terminal status, `ErrStepRunAlreadyFinished`; `OnStepCompleted/OnStepFailed` ignore results for a finished step | DB: second Complete, late failure and stale Update all refused, row unchanged; every terminal status final; live transitions still work. Unit: duplicate completion does not recount or settle the run; late failure does not fail the run |
| **P1.2** | **`partial`** run and step status: migration (CHECKs + `scans.partial_runs`); a batched step with some failed and some completed batches ends `partial`; a run ends `partial` when it has completed and failed/partial steps; `partial` is terminal, counted in `partial_runs`, never auto-retried; web: status badge, filter, one success-rate formula; dead step-level retry removed | DB: run with one failed batch of three → step and run `partial`, counters (total+1, partial+1); retry controller skips partial; terminal guards include partial. Unit: settle matrix (all ok → completed, all failed → failed, mixed → partial). Web: vitest for the formula and badge |
| **P1.3** | **Deadline → `partial` + unfinished targets**: `deadline_at`; reaper ends runs with any completed task `partial` (else `timeout`), records unfinished targets, cancels leased commands; next occurrence plans unfinished targets first | DB: reaper on a run with one completed and one running command → partial, unfinished = the running command's targets, command canceled; next trigger orders unfinished first |
| **P1.4** | *(Started: runs carry `task_summary` and `tasks`, shown in the web Runs tab and run drawer, migration 000761; a run with more than 200 tasks pages the rest through `GET /pipeline-runs/{id}/tasks?cursor=` (keyset on dispatch order, `pipelines:read`, tenant-scoped, the run read returns `tasks_next_cursor`).)* **Runs read model (D2 step 1)**: `GET /scans/{id}/runs` and `/runs/{id}` return trigger, `scheduled_for`, status incl. partial, task summary (done/failed/running/queued, sensors), coverage summary; trigger types `ci`, `retest`, `automation`, `rollover`; CI ingest creates a `trigger=ci` run instead of a `scan_sessions` row; dead `useScanSessions` removed | Route tests incl. cross-tenant 404; CI ingest creates exactly one run per report; web vitest for the runs tab |
| **P1.5** | *(Occurrence key shipped in #949; 15-minute minimum and misfire grace in #1043; `schedule_type` `rrule` (RFC 5545 rule in the scan timezone, migration 000650) shipped; the backfill of legacy daily/weekly/monthly/crontab schedules to rules and the web form remain.)* **Occurrence key + rrule**: `scheduled_for` + `UNIQUE(scan_id, scheduled_for)`; rrule + tz with backfill from daily/weekly/monthly/crontab; minimum interval 15 min; stable jitter; misfire grace | DB: two inserts for one occurrence → one run, the second gets a conflict; rrule property tests (DST, month ends, every-15-min ok, every-5-min refused); backfill test per legacy type |
| **P1.6** | *(Shipped: the skip is checked in `CreateRunIfUnderLimit` under the scan row lock for every scheduled run.)* Overlap check and run insert in one transaction | Race test: manual trigger and scheduler for the same scan concurrently → one active run |
| **P1.7** | *(Shipped for tenant sensors: v2 `capacity` feature, fair order by class with aging then round-robin per run; platform-sensor tenant fair share in #991.)* **Claim-N** with `FOR UPDATE SKIP LOCKED`, server capacity, priority classes with ageing, per-run round-robin | DB: two sensors × N polls never claim the same command; capacity respected; class order; round-robin across two runs; tenant/zone predicates hold |
| **P1.8** | *(Shipped: migration 000770 `controller_leases`; the controller manager runs `Exclusive` controllers — audit, priority-audit, sensor-event and heartbeat-history retention, data expiration, asset purge, threat-intel refresh — under `controller:<name>`; the CT and EASM DNS per-tenant advisory locks are leases.)* **`controller_leases`** + non-idempotent sweeps converted; remove the two session advisory locks | DB: two holders, one wins, epoch increments, expiry hands over; each converted sweep runs once with two instances |
| **P1.9** | *(Started: no id labels on any metric, test-enforced; 17 never-written metrics deleted; `command_claims_total`, `command_leases_expired_total`, `scan_runs_reaped_total` added. `traceparent`, `run_id` log key and `/runs/{id}/explain` remain.)* Observability: `tenant_id` out of metric labels, inert metrics written or deleted, `traceparent` in payloads, `run_id` log key, `/runs/{id}/explain` | Metric label test; explain route tests incl. cross-tenant; trace propagation unit test |
| **P1.10** | Cancel completeness: sdk-go cancel without doorbell; command cancel on scan commands needs `scans:write`; automation cancel stops steps; cancel audited | sdk-go conformance test; route permission test; DB test that automation cancel stops pending steps |
| **P1.11** | *(Started: `tests/integration/two_replica_race_test.go` races two connection pools on one database — scheduler claim + occurrence key, command claim, audit chain — in the API CI test job; controller leases have their own race test with P1.8. A CI job with two API processes and the helm-charts B4 lift remain.)* Two-replica race suite in CI; lift B4 in helm-charts | CI job with two API processes against one DB: scheduler, claim, audit chain, leases |

### P2 — engines and the event backbone

`domain_events` outbox + relay (notifications and the WebSocket move onto it);
engine spec + stage catalogue + validator + builder as the spec editor; stage
chaining through the inventory after ingest commit, exactly once per
`(run, stage)`; templates → engines, presets dropped (B6); `scan_sessions`
retired; Workflows → Automations rename in nav and API (aliases one release).
Aligns with RFC-036 P2–P3.

### P3 — EASM at scale (with RFC-036)

Allow-list scope (B7); EASM tools as catalogue stages (amass/tlsx/alterx and
screenshots per D13); `asset_scan_coverage` side table (D1 data);
`easm_observations` monthly partitions; retention jobs (B11); 200k cap with the
RFC-030 Phase 2 planner.

### P4 — Automations v1 and consolidation

Durable automation runs/steps (B3 after the DBOS spike), CEL filters, waits,
approvals, loop guards, service identity (B5); one `schedules` table; asynq
retired (B10); deterministic dispatch simulator, nightly chaos and load tests,
API↔SDK conformance suite.

## 17. Alternatives considered

- **Temporal / DBOS as the single engine**: cannot run work on remote,
  untrusted, pull-based sensors without a second protocol; merges a data plane
  and a control plane with different trust and scale. Rejected (B2); DBOS only
  as a candidate for automation steps (B3).
- **NATS JetStream / Redis Streams for dispatch**: the claim predicates (zone,
  tool, capability, pinning, class, per-run fairness) are relational and would
  be rebuilt; command state would live in two stores. Rejected below 1,000
  sensors (B1).
- **Keep `scan_sessions` as the run record**: written by nothing today; runs
  already carry everything it would. Retired (D2).
- **A new target gate for scans**: would drift from RFC-042's; reuse instead.

## 18. Compatibility

- API: `/pipeline-runs/*` stays; new fields are additive; `partial` is a new
  enum value — the web and the generated types are updated in the same PR,
  and API consumers treating unknown statuses as "other" keep working.
- Sensors: no protocol change in P1.1–P1.6; claim-N (P1.7) is server-side
  and keeps the v2 poll shape; cancel without doorbell is an sdk-go release.
- Data: migrations are additive; the rrule backfill keeps every existing
  schedule's next occurrence (tested per type).
