# RFC-137: Stage streaming

| | |
|---|---|
| Status | Accepted (2026-10-31). Streaming in the hop router shipped (on by default, `SCAN_STAGE_STREAMING`, per-workflow `stage_barrier`); the run page shows waves from the stage API; item-level pool streaming follows with the target pool |
| Scope | api (scan run scheduler, hop router, stage plan store, stall repair, metrics, workflow setting), docs |
| Architecture | [scan-stages.md §3.6](../architecture/scan-stages.md#36-stage-streaming) |
| Related | RFC-030 (pull, chunks, leases), RFC-040 (signed jobs, sensor-local policy), RFC-046 (Scan, Run, Task; partial runs), RFC-088 (typed units, host chunks), RFC-089 (reach), [finding-closure.md](../architecture/finding-closure.md) (coverage per command) |

## 1. Problem

A chained workflow step is planned only after every predecessor finished and every report of theirs was
ingested (the stage barrier). On live, over 30 days: one httpx task of 72 targets (run time p50 2 428 s)
held the template stage for about 56 minutes, until the run's deadline failed it. Handing a stage a task
costs little: created to acknowledged p50 is 0.3 to 0.4 s for dnsx and naabu. The time is lost waiting at
the barrier, not in round trips.

## 2. Decisions

1. **Stream on the platform, never on the sensor.** The scheduler hands a step the results of each finished
   predecessor task. Every gate stays where it is: the hop router's type contract, strict parse, hop limit,
   fan-out caps, the one target gate (validator, scope exclusions, act scope, zone, ownership and tier),
   delta gating; then the same dispatch (placement, chunking, host keys, the claim-time scope re-check) and
   the signer's statement with an explicit target list; the sensor still re-checks its local policy.
   Chaining on the sensor would need a job signed for a rule ("names under these roots") instead of a list,
   which weakens the strongest property of a job; it would save one hop of seconds.
2. **A wave per finished task, on the inventory.** A wave reads what ingest recorded for the predecessor's
   step run (`scan_step_outputs`), never a sensor's raw output, and only when no report of the predecessor
   is still open (a pending report defers the wave; its commit wakes the next one).
3. **A target is decided once per stage and run.** `scan_run_targets (run_id, stage_key, target_key)` is the
   key; a wave inserts with `ON CONFLICT DO NOTHING ... RETURNING` and dispatches only the planned rows it
   inserted. Waves of one stage run under a per-stage advisory lock, so caps and counts never interleave.
4. **A streamed step settles only after its stream closed.** The closing wave runs once every dependency of
   the step finished and none of their reports is open; it plans what is left, creates its commands, then
   closes the stream. The step's commands count as batches whatever their number; the step settles when the
   stream is closed and no command is active, recorded by whoever sees both last.
5. **On by default, two switches.** `SCAN_STAGE_STREAMING` (default `true`) is the platform switch; a
   workflow keeps every stage behind its predecessors with `stage_barrier: true`. Either off restores the
   barrier exactly.
6. **Smaller source tasks.** A step a successor may stream from is cut into about four tasks (at least 10
   targets each, never above the capability's chunk size): the successor starts on the first quarter of the
   hosts. A hop costs seconds; a barrier on a large step costs minutes.
7. **Coverage stays per command.** A target counts as covered only through a command that ran it and
   reported a per-target outcome `done`; planning a stage never covers anything.

## 3. Design

### 3.1 When a step streams

A pending step S streams from predecessor P when:

- every other dependency of S finished with results (or, with `continue_on_failed_dependency`, finished);
- P is queued or running and has at least one completed task;
- P's stage feeds S's stage (`stage.Feeds`), and S's stage takes a stream: below intrusive (an intrusive
  stage is never fed derived targets), and not a web stage that selects endpoints changed since the run
  started (`endpoint_selector` other than `all`: the selection reads the whole crawl);
- S is not skipped by its condition, the scan's intensity or the run's depth (the barrier pass records
  those skips);
- the run is under its parallel-step limit.

S with two or more unfinished dependencies waits as before: merging partial results of several
predecessors would hand a web stage a name before the origin it is served on.

### 3.2 Waves

| Wave | Trigger | What it plans |
|---|---|---|
| first | a task of P completed (v1) or its report committed (v2) | the ordinary planning: S's seeds plus P's outputs so far, recorded with `streamed = stream_open = true` |
| later | every further completion or commit of a P task | P's outputs no wave of S decided yet |
| closing | every dependency of S finished and no report of theirs is open | what is left; then the stream closes |

A first wave with nothing to dispatch leaves S pending with its stream open; a later wave queues it, or
the closing wave settles it with "no inputs" and the counts. Each later wave recomputes the plan's counts:
planned, the furthest hop and the reasons stored as targets from `scan_run_targets`; inputs and the
reasons not stored as targets (invalid names, duplicates, origins, the seeds' types) from its full read.

### 3.3 Data model

One add-only migration on `scan_run_stage_plans`: `streamed`, `stream_open` (check: never open unless
streamed), `waves`, `first_dispatch_at`, `closed_at`, and a partial index on open streams. Existing plans read
as barrier plans. No new table: the stream is the plan row.

### 3.4 Ordering and consistency

- **Settle race.** A completion of S's last command reads the stream state, then the command counts; the
  closing wave creates its commands, closes the stream, then reads the counts. Each side reads after its
  own write committed, so at least one sees "closed and nothing active" and `ClaimStepFinalization` lets
  exactly one record the outcome.
- **Concurrent waves.** The advisory lock (run, stage) serializes waves across servers; the plan row is
  locked `FOR UPDATE` while a wave writes, and a closed stream takes no wave.
- **Predecessor task retried** (lease expiry, release): same command, its report arrives later and plans a
  wave then. **Failed task:** no outputs; the others are unaffected; P ends `partial`.
- **Lost wake-up** (a report that expired uncommitted): the stall repair also advances a run whose streamed
  step has an open stream and no active command; an open stream is never released as an orphan plan.
- **Crash between a wave's plan and its commands:** its planned targets are not dispatched; coverage is not
  affected (it is per command) and the step's counts show them planned. Rare; accepted.
- **Cancel, deadline, fail-fast:** a finished run takes no more waves; a wave too close to the run's
  deadline records its targets as unfinished (the next run plans them first).

### 3.5 Caps, budgets and fairness

- The fan-out caps (`RunFanoutCap`, per stage, per parent, the step's own `max_targets`) count every wave's
  decisions: a key an earlier wave sent to the gate counts against them. With streaming, which targets a
  cap keeps depends on arrival order; the barrier keeps the first by name.
- Hop limit 3, the tier rule and zone confinement apply per target, unchanged.
- No new claim path: wave commands are ordinary commands, so per-sensor slots, fair share across runs,
  priority classes, windows and politeness keys apply as before. The parallel-step limit counts a streaming
  step as running.

### 3.6 Coverage and closing

Closing (auto-resolve, proposals) is decided per command, from that command's targets and per-target
outcomes. Streaming creates more, smaller commands; each is evaluated on its own. A target planned but not
dispatched, or dispatched in a command that failed, is never covered. A streamed step that lost a task ends
`partial`.

### 3.7 Run progress and UI

`GET /api/v1/scan-runs/{id}/stages` adds `streamed`, `stream_open`, `waves`, `first_dispatch_at` beside the
chunk counts, so the run page can show a stage running while its predecessor still runs. Step status is
unchanged: a streaming step is `queued`/`running` and finishes after its predecessor.

### 3.8 Metrics

| Metric | Meaning |
|---|---|
| `scan_stage_stream_waves_total{kind,outcome}` | kind `start`, `wave`, `close`; outcome `dispatched`, `empty`, `deferred`, `deadline`, `error` |
| `scan_stage_time_to_first_successor_seconds{mode}` | from a source step's start to its streamed successor's first dispatch |
| `scan_stage_barrier_wait_saved_seconds` | how much earlier a streamed stage got its first targets than the barrier would have |

## 4. Threat model

| Threat | Control |
|---|---|
| A derived target skips a gate because it arrives in a later wave | every wave runs the same `deriveStage` (type contract, strict parse, hop limit, caps, target gate, zone, delta) and the same `dispatchStep` (claim-time re-check, signer, host keys); tests cover an excluded and an unconfirmed name in a later wave |
| A sensor injects output to grow another step's input | outputs come only from ingest of a report bound server-side to the command's step run; a sensor cannot name another step, run or tenant |
| Duplicate dispatch (two waves race) | per-stage advisory lock, plan row `FOR UPDATE`, unique target key, dispatch only of rows a wave inserted |
| Fan-out amplification through many small waves | caps count all waves' decisions; waves are bounded by the source's task count; `RunFanoutCap` still bounds the run |
| A step settles early and its last results are dropped, or results are counted as coverage they are not | a streamed step settles only after the stream closed and no command is active; coverage stays per command |
| Cross-tenant reads or writes | every statement is scoped by tenant; rows carry composite tenant foreign keys; the lock key is a run id, which names one tenant's run; tests read, write and close another tenant's stream and get nothing |
| Denial of service through lock waits | the lock wait is bounded (30 s) and a failed wave is retried by the next event or the stall repair |
| Weakened job integrity | none: jobs keep an explicit signed target list; no rule-signed jobs, no sensor-side chaining |

Authorization: no new route and no new permission. The stage API response gains four fields under the
existing `scans:read` gate and run tenant check. The workflow setting is edited with the workflow's existing
write permission; it can only make a workflow wait longer.

## 5. Alternatives

- **Sensor-side chaining** (one job runs discover then resolve locally): rejected (§2.1).
- **Per-target work items with claim-time cutting** (the target pool): the full form of streaming, with
  item-grain retry and back-pressure. It needs per-target outcomes from the progress protocol and a new
  claim path; this RFC streams at task grain now and keeps the same semantics, so the pool can replace the
  waves later without changing what users see.
- **Time-based batching** (plan a wave every N seconds): event-driven waves need no timer and add no latency;
  smaller source tasks give the same effect.

## 6. Tests

- Unit (`internal/app/scanrun/stream_test.go`): a slow task does not block the finished ones' successors;
  dedupe across waves; a failed task loses nothing; every gate on every wave; the switches restore the
  barrier; nothing-to-stream settles only at the end; source splitting; intrusive and endpoint-selecting
  stages never stream.
- Postgres (`internal/infra/postgres/scan_stage_stream_db_test.go`): waves, dedupe, recomputed counts, close,
  cross-tenant negatives, the lock, the stall repair and orphan release.
- Integration on a real database (`tests/integration/stage_streaming_test.go`): the whole flow through the
  scheduler, repositories and commands, including concurrent waves dispatching each target once.

## 7. Not built

Per-target items and claim-time cutting (the target pool); back-pressure between a producer and a slow
consumer beyond the parallel-step limit; streaming from several unfinished predecessors at once; a platform
console switch (the environment switch is the rollback lever; it moves to the console if it is kept past
one release).
