# RFC-030 — Scan work distribution: plan, chunks, leases and fair pull scheduling

> Status: **Accepted for Phases 0–1** (2026-10-02; §9 decisions resolved). Phases 2–4 remain Proposed.
> Scope: api + sdk-go + sensor (`openctemio/sensor`, local checkout `agent`) + ui.
> Builds on: [RFC-007](RFC-007-license-aware-scan-coverage.md) (rolling batch
> coverage, batch-scoped auto-resolve), [RFC-023](RFC-023-scan-zones-and-scanners.md)
> (zones, pinning, the doorbell), [RFC-026](RFC-026-sensor-results-ingest.md)
> (v2 results: idempotent report ids, segments + commit) and
> [RFC-029](RFC-029-sensor-protocol-v2-and-sdk-stability.md) (v2 control plane;
> §4.11 reserved "command leases" and long-poll for a later release; this RFC
> is that release). Consumes the **effective** sensor tools, capabilities and
> `max_concurrent_jobs` (sensor-reported ∩ admin limits), which are being
> built separately; this RFC does not define them.
>
> Owner's request (2026-10-02): "When there is a scan or any command for
> sensors, we need a chunking algorithm and allocation of assets, jobs, … in
> short, the best possible load-distribution algorithm."
>
> Simulation: [RFC-030-sim/scan_distribution_sim.py](RFC-030-sim/scan_distribution_sim.py)
> (standard-library Python, deterministic), output in
> [RFC-030-sim/sim_output.txt](RFC-030-sim/sim_output.txt).

## 1. Summary

Today a scan becomes **one command** (no zones) or **fixed batches pinned to a
sensor at trigger time** (zones). Nothing is re-balanced after trigger time,
the load figures the selector scores are never written, the deployed sensor
claims more work than it can run, and a sensor that dies keeps its work until
the whole run is reaped by a one-hour timeout. Large scans are refused
outright (10,000 targets per run; 1,000 jobs per zoned run, and the default
`targets_per_job` is 1). Single-target scanners (trivy, semgrep, betterleaks)
in a tenant without zones scan **only the first target** of a multi-target
scan.

The proposal replaces "decide at trigger time, push to a sensor" with
**"plan at trigger time, cut and hand out work when a sensor has a free
slot"**:

1. **Plan.** A run's targets are resolved, routed to zones (unchanged,
   RFC-023) and stored as the run's target list with a cost weight and a
   politeness key per target. Nothing is pinned.
2. **Chunk at claim time.** When a sensor polls with free slots, the server
   cuts the next chunk for *that* sensor: as many targets as fit a time budget
   (default 5 minutes) at the throughput measured for this tool on this
   sensor, never more than a fraction of what is left (guided
   self-scheduling), so chunks shrink at the end and no straggler holds the
   run. Slow sensors do not take tail work.
3. **Lease, not ownership.** A claimed chunk carries a lease the sensor renews
   on its heartbeat. A lease that expires (dead or partitioned sensor) puts
   the chunk back on the queue at the front; a chunk that fails on two
   sensors is split to isolate the poison target; results are idempotent per
   chunk attempt, so a late duplicate is harmless.
4. **Fair, priority-ordered queue.** Claims are served by priority class
   (verification and P0 rescans first), then by weighted fair share across
   tenants (platform sensors) and across scans (within a tenant), so a
   50,000-asset coverage scan cannot starve a 50-target manual scan.
5. **Politeness.** Each target has a host key; at most `per_host` chunks
   touch one host at a time and the command carries the rate limit the
   sensor must apply, so distribution never turns into a denial of service
   against the customer's own assets.

In the simulation (heterogeneous fleet of four sensors, 17 slots, one 2.5×
slower; 20 seeds), for a 1,000-target nuclei scan the proposal finishes in
**45 min** against **87 min** today (lower bound 40 min), with slot
utilisation **0.90** against **0.50**. When a sensor dies after 10 minutes,
today's run never completes (25% of the targets are stranded on the dead
sensor and the run is reaped at one hour); the proposal finishes in 65 min.
With fair share, a 50-target scan submitted two minutes after a 1,500-target
scan finishes in **9 min** instead of **137 min** today. §6 has the full table.

## 2. Decisions (proposed)

| # | Decision |
|---|---|
| D1 | **Pull, not push.** The server never decides at trigger time which sensor runs which targets. A sensor with a free slot asks; the server answers from a queue. Trigger-time pinning (`zones.go` least-busy pinning) is removed; zones remain a *filter* (who may claim), not an assignment. |
| D2 | **The unit of distribution is a chunk**, a set of targets of one run for one tool, executed by one command attempt. The command table stays the wire unit, so protocol v1 sensors keep working: a chunk is delivered as an ordinary `scan` command. |
| D3 | **Chunks are cut at claim time** (late binding) from the run's remaining targets, sized by D4. Phase 1 ships fixed-size chunks created at trigger time but unpinned; phase 2 moves the cut to claim time. |
| D4 | **Chunk size targets a time budget** per tool (default 300 s): `n = min(⌊(τ − o) / ĉ(tool, sensor)⌋, ⌈R / (2·S)⌉, n_max(tool))`, `n ≥ 1`. `ĉ` is learned (EWMA of seconds per unit weight, per tool and sensor) with a per-tool prior; failures shrink it multiplicatively (AIMD). |
| D5 | **Capacity is server-side truth.** A sensor's free slots are `effective_max_jobs − (its commands in acknowledged or running)`. The server never hands out more; `current_jobs`, CPU and memory are no longer scheduling inputs (they were never written, §3.5). |
| D6 | **Leases.** A claim sets `lease_expires_at = now + L` (default 3 × the heartbeat interval, clamped 60–300 s). Sensors that negotiated `leases` renew by listing their running commands on the heartbeat. Expiry re-queues the chunk (new attempt, same chunk id). Sensors without the feature keep today's behaviour (no lease, run timeout). |
| D7 | **Bounded retries and poison isolation.** Max 3 attempts per chunk; a chunk that failed on 2 distinct sensors is split in halves; a single target that exhausts its attempts is marked failed and the run ends **partial**, never hung. |
| D8 | **Priority classes then fair share.** Classes: `verify` (validation re-tests, P0 rescans) > `interactive` (manual/quick scans) > `scheduled` > `background` (coverage rotation, RFC-007). Within a class: weighted fair share by start-time fair queuing (virtual time per tenant, then per scan). Ageing promotes a waiting chunk one class after 30 minutes so nothing starves. |
| D9 | **Politeness is part of eligibility.** A chunk is not offered while its host keys already have `per_host` chunks (default 1) in flight; the command carries `limits.rate_limit` and `limits.concurrency`, and an SDK that negotiated `limits` must apply them. |
| D10 | **The run deadline comes from the plan.** The fixed 1-hour default run timeout is replaced by a per-chunk timeout (`3 × τ`, min 10 min) plus a run deadline of `max(scan.timeout_seconds, 3 × estimated makespan)`, capped at 24 h. |
| D11 | **Affinity is optional and soft.** Rendezvous hashing of a target's host key picks a preferred sensor in its zone (warm caches: nuclei templates, git mirrors, trivy DB); the preferred sensor sees the chunk first for a short delay (delay scheduling), then anyone may take it. Off by default. |
| D12 | **Everything new on the wire is additive and feature-gated** (RFC-029 §4.11): `leases`, `capacity`, `limits`, `cancel`, `progress`. |

## 3. Current state (verified on api `develop` 040d9aa0, sdk-go `main` 7f6386b, sensor `main` 6e12c0d)

### 3.1 How a scan becomes commands

`TriggerScan` → `triggerSingleScan` (`internal/app/scan/trigger.go:230`):

1. Smart filtering, then `resolveScanTargets` (`targets.go:54`): direct targets
   + asset-group members − scope exclusions. **Hard cap 10,000 targets**
   (`targets.go:18`, refused at `:119`).
2. If the tenant has zones and the tool reaches the network
   (`zones.go:85`), `planZoneDispatch` (`zones.go:135`) routes targets to the
   narrowest zone, then `planZoneBatches` (`zones.go:145`):
   - batch size `zoneBatchSize` (`zones.go:226`): `targets_per_job` for
     nuclei/tenable/nessus, **1 for every other scanner**; the scan default
     is `TargetsPerJob: 1` (`pkg/domain/scan/entity.go:98`);
   - each batch is **pinned at trigger time** to the zone sensor with the
     fewest active commands (`zones.go:168-187`, `leastLoaded` `:385`),
     counting this run's own batches; capacity and speed are not considered;
   - more than **1,000 batches per run is refused** (`zones.go:205`,
     `TOO_MANY_JOBS`).
   `createZoneCommands` (`zones.go:284`) writes one command per batch with
   `sensor_id` set.
3. Without zones (or for repository/file/container tools), a **single
   command carries every target** (`createScannerCommand`, `trigger.go:460`).
   `applyTargetsToPayload` (`targets.go:136`) sets `target = targets[0]` for
   any scanner other than nuclei/tenable/nessus, and the sensor prefers
   `target` (sensor `pkg/core/command_poller.go:822-825`): **trivy, semgrep and
   betterleaks scan only the first target**. The run says so in a warning
   (`targets.go:123-126`); coverage is still silently 1/n.
4. Workflow scans create one command per step (`queueWorkflowStep`,
   `trigger.go:385`), whole target list, zone-stamped if all targets are in
   one zone, else refused (`ZONE_SPLIT_REQUIRED`, `zones.go:441`).

Completion of a batched step: `checkStepBatches` (`internal/app/pipeline/run.go:735`)
waits for the last batch, then one caller wins `ClaimStepFinalization`. This
part is sound and is reused.

### 3.2 How a sensor is chosen

| Path | What decides | Inputs actually used |
|---|---|---|
| Zoned batch | `RoutableSensors` (`internal/infra/postgres/scan_zone_repository.go:298`) + `leastLoaded`, at trigger time | active command count (real); `current_jobs / max_concurrent_jobs` (always 0, §3.5) |
| Unzoned single scan | **nobody**: the command is unpinned; the first sensor of the tenant that polls takes it | none |
| `SensorSelector.SelectSensor` (`internal/app/sensor/selector.go:105`) | only used to decide *platform vs tenant* (`trigger.go:806`); the adapter **drops the chosen sensor** (`internal/app/adapters.go:131-149`), and in OSS `CanUsePlatformSensors` is always false (`adapters.go:127`) | — |
| Pipeline step | `determineSensorRouting` (`internal/app/pipeline/run.go:385-430`): selector, then `FindAvailableWithTool` ordered by `current_jobs, total_scans` | `total_scans` only |
| Platform queue | `get_next_platform_job` (migration `000230`:170-208): `queue_priority DESC, queued_at` with `FOR UPDATE SKIP LOCKED` | priority + ageing; **`p_capabilities` and `p_tools` are accepted and never used** |

The selector's score (`selector.go:178`, `pkg/domain/sensor/entity.go:534`)
is `0.30·job_load + 0.40·cpu + 0.15·mem + 0.10·disk + 0.05·net` with
`SENSOR_LB_*` weights. Every input is zero in practice (§3.5), and the scan
path discards the result anyway.

### 3.3 Claim semantics

- **Pull with an optimistic claim.** `GET /api/v2/sensor/commands?limit=n`
  (`internal/infra/http/handler/sensor_control_v2_handler.go:218`) →
  `GetPendingForSensor` (`internal/infra/postgres/command_repository.go:119`):
  pinned-to-me or unpinned, ready, zone predicate (`:252`), capability gate
  (`:181`), ordered by priority then `created_at`, **`limit` chosen by the
  sensor (default 10)**, with no reference to the sensor's free slots.
  `claim` is an atomic `UPDATE … WHERE status = 'pending'` (`:322`).
- **The tool gate exists only inside zones.** Scan payloads carry no
  `required_capabilities` (`trigger.go:502-535`), and the poll passes the
  sensor's capabilities, not its tools (`sensor_control_v2_handler.go:225`).
  Outside a zone any tenant sensor can claim a nuclei command it cannot run,
  which is what produced the live `scanner not found: nuclei` failures of
  2026-07-20.
- **No lease.** Recovery is time-based:
  - `recover_stuck_tenant_commands` (migration `000230`:245-272): commands
    **acknowledged** for more than 10 minutes (`internal/infra/controller/job_recovery.go:70`)
    go back to pending and are unpinned; `running` is never touched;
  - commands **pending and pinned** to a sensor that went offline are never
    unpinned (only a zone unassignment unpins, `scan_zone_repository.go:290`);
  - `MarkTimedOutRuns` (`internal/infra/postgres/pipeline_run_repository.go:473`)
    fails every open command of a run after the **run** timeout, default
    1 hour (`pkg/domain/scan/types.go:53`), whatever the run's size;
  - `DefaultCommandTTL` 48 h is the backstop (`pkg/domain/command/entity.go:49`).
- **No cancel.** Canceling a run marks its commands canceled
  (`CancelByPipelineRunID`, `command_repository.go:1282`), but nothing tells a
  sensor; the sensor finishes the scan.

### 3.4 The sensor side

- The daemon runs at most **5 commands, hard-coded** (`main.go:1048`); the
  `-max-concurrent` flag and `internal/config.MaxJobs` do not reach the daemon
  path.
- It **over-claims**: it always polls `limit=10` (sdk-go
  `pkg/client/command.go:71`) and claims each command *before* taking a slot
  (`command_poller.go:468` vs `:478`). With five busy slots it holds up to ten
  acknowledged commands, and the poll loop blocks on the semaphore.
- A failed `start` is only logged (`command_poller.go:515`); execution
  continues.
- Heartbeat `cpu_percent`, `memory_percent`, `active_jobs` are **never
  assigned** in the SDK (`pkg/core/interfaces.go:431-433`) and are dropped by
  `omitempty`; no `max_jobs` is sent.
- `ReportCommandProgress` is a no-op (`pkg/client/command.go:227-235`); no
  partial results; output is buffered and pushed once.
- nuclei: one process per command, `-l` list, fixed `-rate-limit 150 -c 25`
  (`pkg/scanners/nuclei/scanner.go:26,29,473-478`), payload rate limits
  ignored on the daemon path; five slots ≈ 750 requests/s per sensor with no
  per-host cap.
- The doorbell wakes an immediate poll when `pending_jobs > 0`, regardless of
  free slots (`pkg/core/doorbell.go:294-296`).

### 3.5 Inert parts and bugs

| # | Finding | Evidence | Effect |
|---|---|---|---|
| B1 | `sensors.current_jobs` is never written. `ClaimJob`/`ReleaseJob` have no callers; the heartbeat maps `active_jobs` into an in-memory `ActiveJobs` (`internal/app/sensor/service.go:388`) and `UpdateHeartbeat` has no `current_jobs` column (`sensor_repository.go:349-374`). | `sensor_repository.go:581,604`; `service.go:981-987` | Every `current_jobs < max_concurrent_jobs` filter is always true; `job_load` is always 0. |
| B2 | Load metrics are never sent by the sensor (§3.4). | sdk-go `interfaces.go:431-433` | CPU/memory/disk/net terms are 0; the selector ranks on nothing. |
| B3 | The chosen sensor is discarded on the scan path; OSS never uses platform sensors. | `adapters.go:127-149` | `SelectSensor` costs a query and decides nothing. |
| B4 | Single-target scanners scan only `targets[0]` outside zones. | `targets.go:123-144` | A betterleaks/trivy scan of a 1,000-repository group covers one repository. |
| B5 | No tool gate on unzoned scan commands. | `trigger.go:502-535`; `command_repository.go:181` | Sensors claim commands for tools they lack → `scanner not found`. |
| B6 | Over-claim + 10-minute acknowledged reaper + start failure ignored. | §3.3, §3.4 | A claimed-but-waiting command is re-queued while the first sensor still holds it, then both run it: **duplicate scans against customer assets**. |
| B7 | Pending commands pinned to an offline sensor are never unpinned. | §3.3 | A zoned run whose sensor dies waits for the run timeout. |
| B8 | Run timeout is per run, not per unit of work (default 1 h). | `pipeline_run_repository.go:485-499` | A correctly batched large scan is reaped while making progress. |
| B9 | Trigger-time pinning ignores capacity and speed. | `zones.go:168-187` | A 2-slot or slow sensor receives the same number of batches as a 5-slot one; the slowest sets the makespan (§6: utilisation 0.50). |
| B10 | `get_next_platform_job` ignores `p_capabilities`/`p_tools`. | migration `000230`:170-192 | A platform sensor can take a job for a tool it does not have. |
| B11 | Daemon max concurrency is hard-coded 5; the server's `max_concurrent_jobs` (admin, 1–100) is unrelated to it. | sensor `main.go:1048` | Two numbers for one fact (being fixed by the effective-capability work). |
| B12 | Platform-mode vulnscan reports failed or killed tool runs as completed. | sensor `internal/executor/vulnscan.go:206-255` | Silent coverage loss on the platform path. |

### 3.6 What happens in the cases the owner asked about

| Case | Today |
|---|---|
| **50,000-asset scan** | Refused: more than 10,000 targets (`targets.go:119`). Split by hand into 5+ scans; each zoned one needs `targets_per_job ≥ 10` or it is refused at 1,000 jobs; an unzoned one is one command. |
| **Slow sensor** | Zoned: receives its count-share of batches, finishes last. Unzoned: if it polls first, it runs the whole scan. |
| **Sensor dies mid-job** | `running` commands: failed at the run timeout. `acknowledged`: re-queued after 10 min. `pending` pinned to it: stuck until the run timeout. Nothing is re-queued promptly, and the run is lost. |
| **Uneven zones** | Each zone's batches go to that zone's sensors only (correct, RFC-023 D7); a zone with one small sensor gets the same batch size as a zone with ten. No per-zone sizing. |
| **Rate limits per target** | None from the platform. nuclei's fixed per-process limits multiply by the slot count; two batches with targets on the same host can run at once. |
| **Tool-specific cost** | Ignored: one `targets_per_job` per scan; repositories always 1 per job (zoned) or only the first (unzoned). |

## 4. Research: what proven systems do, and what we take

| System | Mechanism | Taken |
|---|---|---|
| **Tenable (Security Center / Vulnerability Management)** | Scan zones map ranges to scanners or scanner groups; a large scan is broken into **scan chunks** that are distributed across the group's scanners as they have capacity, so no scanner owns the whole scan and a lost scanner's chunk can be re-run; per-scanner limits on concurrent scans and hosts. (Exact chunk sizes are product internals and not relied on here.) | Zones as filters (have), chunks handed out on capacity (D1–D3), per-sensor limits (D5). |
| **Rapid7 InsightVM** | Scan engine **pools**: the console load-balances assets across engines in a pool, engines pull, assets of a failed engine re-scanned by others. | Pull + re-queue on failure (D1, D6). |
| **Qualys** | Scanner appliances per network; scan "parallel scaling" splits large target sets across appliances; per-appliance host concurrency and bandwidth caps. | Politeness caps in the command (D9). |
| **nuclei** | `-bulk-size` (hosts in parallel per template), `-c` (templates in parallel), `-rate-limit` (global requests/s), `-rate-limit-duration`, per-host `-max-host-error`. | Chunk carries `rate_limit`/`concurrency` (D9); per-host cap stays a platform property, since nuclei cannot coordinate across sensors. |
| **Celery / Sidekiq / SQS** | Pull with prefetch; **prefetch 1 + late ack** for long tasks (Celery `worker_prefetch_multiplier=1`, `acks_late`), visibility timeout (SQS) = lease; poison messages to a dead-letter queue after N receives. | Free-slot-bounded poll (D5), leases (D6), max attempts + poison handling (D7). |
| **Temporal** | Activity task queues polled by workers; **heartbeat timeout** on long activities (lease), start-to-close and schedule-to-close timeouts, retries with backoff, idempotent completion. | Per-chunk timeout and run deadline (D10), lease via heartbeat (D6). |
| **Work stealing / guided self-scheduling** (Cilk; Polychronopoulos & Kuck 1987; factoring, Hummel 1992) | Hand out large chunks first, shrinking as work runs out, so the tail is balanced without per-item overhead. | `⌈R / 2S⌉` cap (D4). |
| **AIMD** (TCP; adaptive batch sizing in Kafka/Flink back-pressure) | Grow additively on success, cut multiplicatively on a congestion signal. | Chunk size shrinks ×0.5 on timeout/OOM, recovers additively (D4). |
| **Fair queuing** (DRR, Shreedhar & Varghese 1995; SFQ, Goyal 1996; YARN/Slurm fair-share with decay) | Per-flow virtual time; serve the smallest; weights per class; decayed usage. | Hierarchical fair share tenant → scan (D8). |
| **Delay scheduling** (Zaharia et al., 2010) + **rendezvous hashing** | Wait briefly for a node with locality before giving up locality; stable owner per key with minimal reshuffle on membership change. | Optional affinity (D11). |
| **Heterogeneous scheduling** (HEFT; LATE straggler handling, Zaharia 2008) | Estimate per-node speed; do not give the critical tail to slow nodes; speculative re-execution. | Tail rule (§5.2). Speculative re-execution **rejected**: running a scan twice doubles load on customer assets. |

## 5. Design

### 5.1 Model

```
scan ──trigger──▶ run ──plan──▶ run targets (ordered, weighted, zoned, host key)
                                   │
                    sensor polls with free slots
                                   ▼
                         chunk (targets [i..j) of one zone, one tool)
                                   │  one command per attempt (wire unit)
                                   ▼
                     lease ─renew on heartbeat─▶ complete │ fail │ expire → re-queue
```

New tables (one migration, add-only):

```sql
-- the run's work list; written once at trigger time
CREATE TABLE scan_run_targets (
  run_id     uuid    NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
  ord        integer NOT NULL,          -- planner order (criticality, then locality)
  tenant_id  uuid    NOT NULL,
  target     text    NOT NULL,
  zone_id    uuid,                      -- NULL: unzoned
  host_key   text    NOT NULL,          -- politeness key (§5.6)
  weight     real    NOT NULL DEFAULT 1,-- cost units (§5.2)
  chunk_id   uuid,                      -- set when cut
  state      text    NOT NULL DEFAULT 'pending', -- pending|leased|done|failed|skipped
  PRIMARY KEY (run_id, ord)
);
CREATE INDEX ON scan_run_targets (run_id, zone_id, state, ord);

CREATE TABLE scan_chunks (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  run_id      uuid NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
  step_run_id uuid,
  zone_id     uuid,
  tool        text NOT NULL,
  class       text NOT NULL,            -- verify|interactive|scheduled|background
  targets     integer NOT NULL, weight real NOT NULL,
  attempt     integer NOT NULL DEFAULT 0, max_attempts integer NOT NULL DEFAULT 3,
  failed_on   uuid[] NOT NULL DEFAULT '{}',  -- sensors it failed on (poison rule)
  command_id  uuid,                     -- current attempt
  sensor_id   uuid,
  lease_expires_at timestamptz,
  state       text NOT NULL,            -- queued|leased|done|failed|split
  est_seconds real, started_at timestamptz, finished_at timestamptz
);
ALTER TABLE commands ADD COLUMN chunk_id uuid, ADD COLUMN lease_expires_at timestamptz;
```

The run keeps one step run; `checkStepBatches` already completes a step when
its last command ends and keeps working (chunks are commands of that step).

Throughput history lives in a small table keyed `(tenant_id, tool,
sensor_id)` with the EWMA of seconds per unit weight and a sample count
(§5.2); the per-tool prior is a `tools.metadata.cost_seconds_per_unit` value
(no schema change).

### 5.2 Chunk size

Notation: `τ` time budget per chunk (per tool, default 300 s), `o` fixed
per-command overhead (process start, template load, result upload; learned,
prior 10 s), `ĉ(t, s)` seconds per unit weight of tool `t` on sensor `s`, `R`
remaining weight in the claimable part of the run, `S` live slots that may
claim it (effective max jobs of the zone's healthy sensors), `n_max(t)` tool
limit (1 for single-target scanners until the sensor advertises a
multi-target executor for the tool, else 500).

```
weight(target)  = 1                               host, URL, domain
                = min(hosts in CIDR, 4096) / 16   network range (nuclei/nmap cost ~ live hosts)
                = clamp(repo_size_mb / 50, 1, 20) repository (trivy/semgrep/betterleaks)

ĉ(t, s) ← (1 − α)·ĉ(t, s) + α·(wall − o) / weight(chunk)        α = 0.3, on success
ĉ(t, s) ← prior(t)·speed_hint(s)  while samples(t, s) < 3       cold start

budget_n = ⌊(τ − o) / ĉ(t, s)⌋                  fill the time budget
gss_n    = ⌈R / (2·S)⌉                          guided self-scheduling: shrink near the end
n        = clamp(min(budget_n, gss_n, n_max(t)), 1, R)   (in weight units, then whole targets)

AIMD on the chunk outcome for (t, s):
  timeout / OOM / killed  → τ_eff(t, s) ← max(τ_min, τ_eff / 2)
  success                 → τ_eff(t, s) ← min(τ, τ_eff + τ/10)
```

**Tail rule.** A sensor whose `ĉ` is more than 1.5× the best live sensor's for
the tool does not claim from a run whose remaining weight is below two
chunks per fast slot; it moves to other work or idles. This is what keeps a
slow sensor from becoming the straggler (in the simulation it is the
difference between 0.80 and 0.90 utilisation).

Why claim time and not trigger time: the size depends on *who* claims
(`ĉ(t, s)`) and on *how much is left* (`R`, `S`), both known only then. A
trigger-time plan can only use a fleet-average guess and cannot react to a
sensor joining, leaving or slowing down.

### 5.3 Selection on poll

```
on poll(sensor s, requested k):                       # k ≤ free slots, D5
  free  = effective_max_jobs(s) − count(commands of s in acknowledged|running)
  k     = min(k, free);  if k == 0: return []
  out   = expired-lease or retry chunks eligible for s, front of queue   # D6/D7
  while len(out) < k:
    cands = runs with claimable targets where
              zone(run part) ∈ zones(s) or unzoned,                 # RFC-023 layer 2
              tool ∈ effective_tools(s),                            # fixes B5
              platform/tenant rule holds,                           # D14 of RFC-023
              not tail-blocked for s (§5.2),
              politeness: some target whose host_key has < per_host in flight
    if cands empty: break
    r     = pick(cands)                                             # below
    chunk = cut(r, s, size(r, s))      # SELECT … FOR UPDATE SKIP LOCKED on scan_run_targets
    out  += chunk
  for c in out: create command (pinned to s, acknowledged, lease = now + L)
  return out

pick(cands):                                           # D8, hierarchical SFQ
  class* = highest class present (after ageing: +1 class per 30 min waited)
  tenant = argmin over tenants in class* of VT_tenant          (platform sensors only;
                                                                 tenant sensors: one tenant)
  run    = argmin over runs of tenant in class* of VT_run
  on dispatch of chunk with estimated cost e:
     VT_tenant += e / w_tenant ;  VT_run += e / w_run
  a newly backlogged tenant/run starts at max(own VT, min VT of backlogged peers)
```

The claim is one transaction: lock the run's next claimable targets with
`FOR UPDATE SKIP LOCKED`, insert the chunk and command, mark the targets
`leased`. Two sensors polling at once cut disjoint chunks. Today's v1/v2
`claim` route stays: the command it returns is already acknowledged to the
caller, so a replayed `claim` is the existing `200 replay`.

Weights: `w_run` = 1 by default, 4 for `interactive`, configurable per scan;
`w_tenant` = 1 (platform plans may set it). Virtual times are kept in memory
per API instance and reconstructed from `scan_chunks` (sum of `est_seconds`
over the last 30 minutes) on start, so several API replicas converge without
coordination; exactness across replicas is not required for fairness to hold
within a few chunks.

### 5.4 Leases, failure, poison, cancel

- **Lease length** `L = clamp(3 × next_heartbeat_seconds, 60, 300)` s.
- **Renewal.** With feature `leases`, the heartbeat carries `"running":
  ["<command_id>", …]`; the server extends those leases (only commands that
  belong to the sensor, `acknowledged` or `running`). The response lists any
  id it did not renew in `"lost": [...]` (canceled, expired, reassigned), and
  the sensor stops that work.
- **Expiry** (controller, every 15 s): command → `failed` with
  `LEASE_EXPIRED`; chunk → `queued`, `attempt + 1`, its targets back to
  `pending`; it is served before new work.
- **Failures** follow the same path with the sensor's error. A chunk whose
  `failed_on` holds two distinct sensors is **split** into halves (state
  `split`, two child chunks). A one-target chunk that reaches `max_attempts`
  marks its target `failed`; the run ends `partial` with the target list.
- **Late results** from a lost lease: results are keyed by the chunk attempt
  (`report_id = chunk_id + attempt`, RFC-026 idempotency), so a duplicate is
  accepted once and auto-resolve stays scoped to the report's assets
  (RFC-007 invariant). The late `complete` gets `409 lease-lost`; data is
  never discarded.
- **Without the feature** (v1 and old v2 sensors): no lease; the legacy
  10-minute acknowledged reaper stays for them only; `running` is bounded by
  the per-chunk timeout (D10) instead of the run timeout.
- **Cancel.** With feature `cancel`, heartbeat `actions` gains `cancel` with
  `cancel_command_ids`; the SDK cancels the command's context (process group
  kill). Run cancel = cancel all its leased chunks + drop queued ones.

This also closes B6 and B7: a sensor never holds more than it can run (D5),
and nothing is pinned until it is leased.

### 5.5 Progress, ETA and timeouts

Per run, from `scan_run_targets` and `scan_chunks` (one aggregate query,
returned with the run on the existing run API):

```
done_frac = Σ weight(done) / Σ weight(all)
rate      = Σ over live leases' sensors of slots_s / ĉ(t, s)          (weight units per second)
ETA       = Σ weight(pending ∪ leased) / rate      (shown as a range: ±1 σ of ĉ)
```

Run deadline per D10; a run that passes it ends `partial` (done targets keep
their results; pending ones are listed), never `timeout` with nothing.
`scan.timeout_seconds` becomes the *minimum* deadline, so existing scans do
not get shorter limits.

### 5.6 Politeness

- **Host key**: IP for addresses; registrable domain (public suffix list) for
  hostnames and URLs; `scm_host/owner` for repositories; the CIDR for ranges.
- **Eligibility**: a target is claimable only if its host key has fewer than
  `per_host` targets leased (default 1, per zone setting); the cutter skips
  blocked targets rather than waiting, so one hot domain never stalls a chunk.
- **In the command** (`limits`): `rate_limit` (requests/s for the chunk,
  default from the zone: `zone.max_rps / max(1, leased chunks in zone)`),
  `concurrency`, `per_host_concurrency`. The SDK passes them to nuclei
  (`-rl`, `-c`, `-bs`, `-mhe`); today the daemon path ignores payload limits.
- **Scan windows** (optional, per zone): no new chunk is cut outside the
  window; leased chunks finish.

### 5.7 Multi-tenant fairness and quotas

Tenant sensors only ever serve their own tenant, so fairness there is across
scans of the tenant (§5.3). Platform sensors serve many tenants: the tenant
level of the hierarchy applies, plus a per-tenant cap on leased chunks
(replacing `calculate_queue_priority`'s active-job penalty) and the tool gate
that `get_next_platform_job` lacks (B10). `MaxConcurrentRunsPerTenant` (50)
stays as an admission limit; it no longer has to double as a fairness tool.

**Status (RFC-046 P1.7, migration 000461):** `get_next_platform_job` orders
the shared queue by priority class (one class up per 30 minutes queued,
never into critical), then by the tenant's platform jobs in flight (fewest
first), then `queue_priority` and age; the tool and capability gates (B10)
shipped in 000251. The per-tenant cap on leased jobs is not in yet: ordering
alone keeps a quiet tenant from waiting behind a busy one, and a cap would
idle shared sensors when one tenant is alone.

### 5.8 Inputs replaced

| Today | After |
|---|---|
| `current_jobs` (never written) | count of the sensor's `acknowledged`/`running` commands (index on `commands(sensor_id, status)`) |
| CPU/memory/disk/net weights (`SENSOR_LB_*`) | not scheduling inputs; kept as display metrics. The env vars are accepted and ignored with a one-time warning, then removed after a release. |
| admin `max_concurrent_jobs` vs sensor's hard-coded 5 | `effective_max_jobs` from the capability work |
| `targets_per_job` | an upper bound (`n_max`) when set; otherwise D4 |
| `maxResolvedTargets` 10,000, `maxZoneJobsPerRun` 1,000 | 200,000 targets per run (bounded by the planner insert, ~30 MB); no job cap (chunks are cut lazily) |

#### 5.8.1 The sensor's load report (owner decision 2026-10-02: "the SDK computes resources, nothing hard-coded")

The SDK, not each sensor, measures the machine it runs on and derives its
own job slots; the sensor only registers executors. On every heartbeat
(feature `load`, additive, all optional):

| Block | Fields | Source in the SDK |
|---|---|---|
| `resources` | `cpu_cores`, `cpu_used_pct`, `mem_total_bytes`, `mem_available_bytes`, `load1`, `disk_free_bytes` | cgroup-aware (v2 `cpu.max`/`memory.max`, v1 CFS quota/`memory.limit_in_bytes`, cpuset), not host totals; disk free on the work dir |
| `capacity` | `slots_total`, `slots_free`, `active_jobs`, `per_tool.<tool>.{est_cpu_s, est_mem_bytes, throughput_targets_per_min}` | `slots = clamp(min(configured cap, ⌊cpu_avail / est_cpu_per_job⌋, ⌊mem_avail / est_mem_per_job⌋), 1, hard_max)`, per-tool estimates learned from completed jobs (persisted locally), AIMD on OOM/timeout/throttling |
| `queue` | `claimed`, `running`, `queued_local`, `oldest_age_seconds` | the SDK's local work queue (§5.12) |

The API clamps every value (NaN/negative → 0, bounded sizes, at most 64
`per_tool` entries with tool-like names) and stores the latest snapshot
(`sensors.reported_resources/_capacity/_queue`, `load_reported_at`,
migration 000254). It is shown on the sensor API (`load`, with `fresh`) and
used for dispatch while **fresh (3 minutes)**:

- **free slots** = `effective_max_jobs − commands the sensor holds`
  (acknowledged or running, counted from `commands`: the server truth, D5),
  and no more than a fresh `capacity.slots_free`. The report can only
  lower it. The command poll never offers more **scan** commands than the
  free slots (Phase 1.2, shipped with Phase 0); selection skips sensors with
  no free slot and orders by free slots, then by the reported
  `throughput_targets_per_min` for the tool.
- `resources.cpu_used_pct` and memory in use feed the existing load score
  when the sensor does not send the legacy percentages.
- `per_tool` throughput and cost are the **prior for `ĉ(t, s)`** (§5.2):
  Phase 2's chunk sizing starts from what the sensor measured instead of a
  fleet-wide guess, and its own EWMA takes over after three samples.

`sensors.current_jobs` (never written, B1) is no longer read; `ClaimJob` /
`ReleaseJob` (no callers) are deleted. "Is there a capable sensor" gates (the
trigger's `NO_SENSOR_AVAILABLE`, the validation gate) still ask for an
online capable sensor, not a free one, so a busy fleet queues work instead
of refusing it; a tenant whose capable sensors are all busy keeps the job
(`TenantBusy`), it never moves to shared sensors.

### 5.9 Protocol (v2, additive; v1 unchanged)

`GET /hello` features: `leases`, `capacity`, `limits`, `cancel`, `progress`.
A sensor opts in by naming them in `OpenCTEM-Sensor-Features` (RFC-029 §4.11).

| Where | Addition |
|---|---|
| `POST /heartbeat` request | `max_jobs` (what the sensor can run), `running` (command ids it holds), `free_slots` |
| `POST /heartbeat` response | `lost` (ids not renewed), `actions: ["cancel"]` + `cancel_command_ids` |
| `GET /commands` | `limit` is honoured as **at most the free slots**; with `capacity` the response is already claimed (`acknowledged`, lease set), so the sensor skips `claim` (a `claim` replay still answers `200`) |
| `Command` | `lease_expires_at`; `chunk: {"id", "attempt", "targets", "of_run_targets"}`; `limits: {"rate_limit", "concurrency", "per_host_concurrency"}` |
| `POST /commands/{id}/progress` (`progress`) | `{"done_targets": n, "report_ids": [...]}`; renews the lease too |
| Problems | `409 lease-lost` |

sdk-go: poll with `limit = free slots` and claim *after* taking a slot (fixes
the over-claim for every sensor, feature or not); send `max_jobs`, `running`;
honour `lost`/`cancel`; apply `limits`; report real `active_jobs`. Sensor:
expose `max_jobs` config (env + flag) on the daemon path.

### 5.10 Observability

Metrics (Prometheus, no tenant label on the platform-wide series):
`scan_chunk_wait_seconds{class}` (queued → leased), `scan_chunk_run_seconds{tool}`,
`scan_chunk_size_targets{tool}`, `scan_chunk_attempts_total{outcome}`
(done/failed/lease_expired/split/poison), `scan_lease_expired_total`,
`sensor_slots{state=free|leased}` (fleet), `scan_queue_depth{class}`,
`scan_cost_estimate_error_ratio{tool}` (predicted vs actual, to tune τ),
`scan_politeness_deferred_total`. Per run: a timeline of chunk events
(cut/leased/renewed/done/failed/re-queued) in `scan_chunks`, retained with
the run.

### 5.11 UI

- Run detail: progress bar by weight, ETA range, chunk table (state, sensor,
  targets, attempt, duration), failed/partial targets with reasons, a
  Gantt-style lane per sensor.
- Sensors page: slots used/free, throughput per tool (`1/ĉ`), lease
  expiries in the last 24 h.
- Scan form: priority class; `targets_per_job` moves to "Advanced: max
  targets per job".

### 5.12 Two queues: the platform's and the sensor's (owner decision 2026-10-02)

"The sensor must manage its queue — or is it the platform? It must be from
the SDK." Two layers, with one owner each:

| | Platform queue (authoritative) | Sensor local queue (sdk-go) |
|---|---|---|
| Holds | every run's work: priority classes, fair share, chunks, leases, retries (this RFC) | only what this sensor has claimed: at most its free dynamic slots, no prefetch |
| Decides | **what** runs and **where** | **when** a claimed command starts on this machine |
| Ordering | class → fair share (§5.3) | the command's priority/class among what it holds |
| Politeness | `per_host` eligibility across the fleet (§5.6) | per-target-host limits from the command's `limits`, on this machine |
| Failure | lease expiry → re-queue (§5.4) | renews leases of queued + running items on the heartbeat (`running`); on cancel stops the command; on drain stops claiming, finishes within a grace period, and **releases** the rest |

A sensor implements executors; the SDK owns the local queue, slots,
leases and reporting (sdk-go README "Writing a sensor").

**Release** (feature `release`): `POST /api/v2/sensor/commands/{id}/release`
`{"reason": "draining"}` hands a command the sensor holds (acknowledged or
running) back to the queue at once: pending, unpinned, zone kept, the reason
stored, not counted as a dispatch attempt. Only the holding sensor may
release it (else 404); a repeat answers the command as it is; a finished
command answers 409. Without it a draining sensor's work waited for the
10-minute acknowledged reaper (or, with leases, the lease). A v1 sensor has
no release; the SDK falls back to `fail` with `released: <reason>`.

## 6. Simulation

`docs/rfcs/RFC-030-sim/scan_distribution_sim.py`, 20 seeds per row, median
makespan. Fleet: s1 and s2 5 slots, s3 2 slots, s4 5 slots at 2.5× slower
(17 slots, 14 speed-equivalent). Per-target cost log-normal (nuclei median
20 s σ 1.0; betterleaks median 25 s σ 1.5, heavy tail), 8 s per-command
overhead, 120 s lease, 1 h run timeout. "done ≤ 1 h" is the share of targets
whose results arrived before today's default run timeout; "scanned" the
share ever scanned.

```
## big_nuclei  (1,000 nuclei targets; lower bound max(work/capacity, max target) = 39.8 min)
policy                       makespan(min)  finished   util done<=1h scanned
current_unzoned                      556.7     20/20   0.06     0.00   1.000
current_zoned batch=1                 86.3     20/20   0.60     0.86   1.000
current_zoned batch=50                86.6     20/20   0.50     0.72   1.000
pull_fixed batch=50                   83.7     20/20   0.55     0.80   1.000
pull_fixed batch=10                   50.5     20/20   0.80     1.00   1.000
pull_adaptive                         44.9     20/20   0.90     1.00   1.000

## big_nuclei_death  (same, s2 dies at 10 min)
current_zoned batch=50                 inf      0/20   0.56     0.47   0.750
pull_fixed batch=50                   85.3     20/20   0.70     0.66   1.000
pull_adaptive                         64.8     20/20   0.91     0.98   1.000

## repos  (1,000 repositories, betterleaks; lower bound 90.7 min)
current_unzoned                        0.5     20/20   0.06     0.00   0.001
pull_fixed batch=1                   136.6     20/20   0.74     0.63   1.000
pull_fixed batch=20                  144.7     20/20   0.64     0.51   1.000
pull_adaptive                        124.6     20/20   0.75     0.64   1.000

## multitenant  (A 1,500 targets at t=0, B 50 at 2 min, C 200 at 5 min; per-scan latency)
current_zoned batch=50               154.6     20/20   0.52     0.64   A=133.2 B=136.7 C=134.6
pull_fixed batch=50                   93.6     20/20   0.71     0.62   A=84.5  B=73.1  C=83.2
pull_adaptive fairness=fifo           77.2     20/20   0.93     0.85   A=65.9  B=65.6  C=71.6
pull_adaptive fairness=drr            76.9     20/20   0.94     0.80   A=76.9  B=9.4   C=17.3
```

Reading:

- **Coarse, pinned batches are the main loss.** Same batches, unpinned (`pull_fixed 50`) vs
  pinned (`current_zoned 50`): small gain alone, because 50-target batches are
  too coarse (20 chunks over 17 slots); with smaller fixed chunks (10) pull
  already reaches 0.80 utilisation and 50 min. Adaptive sizing + tail rule
  takes it to 0.90 and 45 min, 13% above the lower bound.
- **Failure handling decides whether a run completes at all.** Today a dead
  sensor strands its pinned batches until the run timeout (75% scanned, run
  failed). Leases re-queue them two minutes later.
- **Repositories today are a coverage bug, not a speed one**: 1 of 1,000
  scanned. With one-repository chunks the gap to the lower bound is the heavy
  tail of single huge repositories, which no chunking can split; the fix there
  is the per-chunk timeout + a weight from repository size so huge
  repositories start first.
- **Fair share costs the big scan 11 minutes and saves the small ones two
  hours**: B 137 → 9 min, C 135 → 17 min, at the same total makespan.

Limits of the model: costs are independent per target (no shared-host
contention), one scanner process per slot, perfect lease timing, no network
or API latency, no politeness constraint (which can only lengthen
makespans of scans concentrated on few hosts). It compares policies; it does
not predict wall-clock times of a real fleet. Phase 2 ships with the
`scan_cost_estimate_error_ratio` metric to calibrate the priors.

## 7. Phased plan

Each line is one PR unless marked. "Safe" = no protocol change, no behaviour
change for a sensor, revertible.

| Phase | PR | Repo | Content | Risk |
|---|---|---|---|---|
| **0 — fix what is broken** (safe, ship first) | 0.1 | api | Tool gate for every scan command: put `required_tools` in the payload and filter the poll by the sensor's (effective) tools; same for `get_next_platform_job` (B5, B10). | Low. A sensor that lied about tools stops getting work it fails anyway. |
| | 0.2 | api | Unpin pending commands of a sensor that goes offline (in `SensorHealthController.onOffline`), zone stamp kept (B7). | Low. |
| | 0.3 | api | Fan out single-target scanners: one command per target outside zones too (reuse `chunkTargets` with size 1, the batch completion already exists) (B4). Raises command count; keep the 1,000 cap per run for now and refuse above it with a clear message. | Medium: more commands per run; covered by the step batch gate. |
| | 0.4 | sdk-go + sensor | Poll `limit = free slots`, take the slot **before** claiming; abort execution when `start` fails with `409`; send real `active_jobs` and `max_jobs`; daemon `max_jobs` configurable (B6, B2, B11). | Low; conformance tests. |
| | 0.5 | api | Delete the dead inputs: `ClaimJob`/`ReleaseJob`, `current_jobs` filters → computed from commands; selector reduced to "has a capable online sensor" (B1, B3). | Low; `current_jobs` stays as a column until a later migration. |
| | 0.6 | sensor | Platform vulnscan: failed tool run → failed command (B12). | Low. |
| **1 — pull with fixed chunks and leases** | 1.1 | api | Stop trigger-time pinning: zone batches are created unpinned with the zone stamp; the zone claim predicate already restricts who may take them. Batch size = `targets_per_job` or a per-tool default (nuclei 25, others 1). | Medium: changes distribution only; rollback = re-enable pinning flag. |
| | 1.2 | api | Server-side capacity: poll returns at most `effective_max_jobs − active` (D5). | Low. |
| | 1.3 | api + sdk-go | Leases: `commands.lease_expires_at`, heartbeat `running`/`lost`, expiry controller, `leases` feature, `409 lease-lost`; max attempts + split on two-sensor failure (D6, D7). | Medium: new controller; feature-gated. |
| | 1.4 | api | Per-command timeout + run deadline from the plan; run ends `partial` (D10, B8). | Medium: changes run outcomes; old scans keep at least their configured timeout. |
| | 1.5 | ui | Run progress by batch, partial runs, sensor slots. | Low. |
| **2 — adaptive chunks cut at claim time** | 2.1 | api | `scan_run_targets`, `scan_chunks`, planner writes targets at trigger time; raise the target cap; cut on poll with `FOR UPDATE SKIP LOCKED`. Behind `SCAN_CHUNKING=adaptive` (default `fixed`). | High: new hot path; load-test the claim transaction at 50 polls/s. |
| | 2.2 | api | Throughput history + `ĉ`, budget/GSS/AIMD sizing, tail rule, weights (repo size, CIDR). | Medium. |
| | 2.3 | api + ui | ETA, chunk timeline, metrics (§5.10); `scan_cost_estimate_error_ratio` before the default flips to `adaptive`. | Low. |
| **3 — fairness and priority** | 3.1 | api | Priority classes on scans and validation/rescan commands; ageing. | Low. |
| | 3.2 | api | Hierarchical fair share (tenant → run) on the claim path; per-tenant cap on platform sensors. | Medium. |
| **4 — politeness, cancel, affinity** | 4.1 | api + sdk-go | Host keys, `per_host` eligibility, `limits` in commands and applied by the SDK; zone `max_rps`; scan windows. | Medium: can lengthen scans concentrated on few hosts (intended). |
| | 4.2 | api + sdk-go + sensor | `cancel` action, process-group kill. | Low. |
| | 4.3 | api + sdk-go | `progress` + partial commit per chunk segment. | Low. |
| | 4.4 | api | Optional affinity (rendezvous + delay scheduling), off by default. | Low. |

RFC-023's sensor-side allow-list (layer 3) is unaffected: chunks only narrow
what a command carries.

## 8. Risks

- **Claim-path cost.** Cutting chunks on poll puts a write transaction on
  every poll that finds work. Mitigation: the doorbell already rate-limits
  polling; the cut is index-range bound (`run_id, zone_id, state, ord`); load
  test before flipping the default.
- **Estimator drift.** A bad `ĉ` gives chunks that are too large (late
  failure, retried) or too small (overhead). Bounded by `n_max`, AIMD and the
  per-chunk timeout; observable via the error-ratio metric.
- **Behaviour change for operators who rely on pinning.** None can pin today
  except through zones, which remain; the `sensor_id` pin of pipeline steps
  stays for workflows until a workflow is chunked (out of scope).
- **Mixed fleets.** v1 sensors get commands without leases; they keep the old
  recovery rules. Fairness and sizing still apply to them, since both are
  server-side.
- **Politeness vs speed.** `per_host = 1` serialises scans of a single big
  web property. Per-zone setting; default chosen for safety.
- **Monorepo cutover.** This RFC lands in api `docs/rfcs`; it moves with the
  repository.

## 9. Decisions (resolved 2026-10-02)

The owner decided items 1, 3, 4 and 6; items 2, 5 and 7 were left to the
implementer and take the RFC's proposal. All seven are settled; Phases 0–1
are accepted for implementation on that basis.

| # | Question | Decision | By |
|---|---|---|---|
| 1 | Priority classes and their order (D8) | **`verify > interactive > scheduled > background`, with ageing** (§5.3). A manual rescan that verifies a P0 finding is `verify`. | owner |
| 2 | Fairness unit on tenant sensors | **Per scan** (each scan's run is a flow), as proposed. | default |
| 3 | Default politeness | **On by default**: `per_host = 1` (one chunk in flight per target host) and a sane per-zone rate (`max_rps`, default 300 req/s), **overridable by an administrator per scan profile**. | owner |
| 4 | Partial runs | **Agreed.** A run that loses targets ends `partial`; successful findings are kept; **"Retry failed" re-runs only the failed chunks**, never the whole run. | owner |
| 5 | Target cap per run | **200,000** targets per run (bounded by the planner insert). Phase 0 keeps today's caps (10,000 targets; 1,000 commands per run) because it still creates every command at trigger time; the cap is raised with the Phase 2 planner. | default |
| 6 | Ship Phase 0.3 (fan-out of single-target scanners) early | **Yes, now, in Phase 0**: one command per target for single-target scanners outside zones too. | owner |
| 7 | Speculative re-execution of stragglers | **Rejected**: never re-run a slow chunk on a second sensor (double load on customer assets). | default |

## Appendix A — size and pick, as code

```go
// chunkSize returns how many targets of run r the sensor s should take now.
func chunkSize(r RunState, s SensorState, t ToolState) int {
	c := t.SecondsPerUnit(s.ID)                 // ĉ, prior until 3 samples
	budget := s.EffectiveBudget(t.Name)          // τ after AIMD, ≤ t.Budget
	byBudget := int((budget - t.Overhead) / c)   // weight units that fit the budget
	gss := ceilDiv(r.RemainingWeight, 2*r.LiveSlots)
	n := min(byBudget, gss, t.MaxTargets)
	return clamp(n, 1, r.RemainingTargets)
}

// tailBlocked keeps a slow sensor off the end of a run.
func tailBlocked(r RunState, s SensorState, t ToolState) bool {
	best := r.BestSecondsPerUnit(t.Name)
	return t.SecondsPerUnit(s.ID) > 1.5*best && r.RemainingWeight <= 2*r.FastSlots(1.5*best)
}

// onOutcome updates the estimator and the AIMD budget.
func onOutcome(t *ToolState, s SensorID, wall, weight float64, ok bool) {
	if ok {
		t.Observe(s, (wall-t.Overhead)/weight) // EWMA α = 0.3
		t.GrowBudget(s, t.Budget/10)           // additive increase
	} else {
		t.HalveBudget(s)                       // multiplicative decrease, ≥ τ_min
	}
}
```
