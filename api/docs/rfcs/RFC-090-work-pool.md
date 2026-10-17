# RFC-090: Work pool

| | |
|---|---|
| Status | Accepted (2026-10-13); W0–W2 in progress, the rest designed |
| Scope | api (planner, claim, settlement, streaming, metrics), ctis (`politeness`), sdk-go (progress with finished targets, yield), sensor (picks up the SDK), web (run Work panel, Scans → Queue) |
| Architecture | [scan-orchestration.md](../architecture/scan-orchestration.md), [scan-stages.md](../architecture/scan-stages.md) |
| Amends | RFC-030 §5.1–§5.3 (its Phase 2, claim-time cutting, becomes this pool), RFC-046 §5.2 (planning per run, stage and unit; streaming between steps) |
| Related | RFC-030 (pull, leases, fair share; decisions §9), RFC-040 (claim-time signed jobs, local policy), RFC-046 (Scan → Run → Task), RFC-074 (adaptive control), RFC-088 (typed work units, pieces, host keys), RFC-089 (network context, reach outcomes) |

## 1. Summary

The platform splits a run's targets into a **pool** of small typed items;
a sensor that asks takes from the pool only what it may run. The pool holds
one item per unit (RFC-088: a name, an address, a range piece, a URL, a
service) per step; the wire still carries **batches**: a claim cuts a task of
many items of one lane for that sensor, sized by what that sensor can finish
in a time budget. Results settle items, not commands, so retry, reroute,
stall handling and resume work at item grain, and each finished task streams
its outputs into the next step at once.

This is the unbuilt half of RFC-030. Its Phases 0–1 shipped (unpinned
commands, leases, host keys, step chunks, round-robin across runs); its
Phase 2 (cut at claim time from a per-run target list) did not, so today the
"pool" is the `commands` table holding batches cut when a step starts.

Two live faults are pool problems:

- **Barrier plus fixed batches.** One 72-target probe command ran ~40 min;
  the template step waited behind the barrier for ~56 min and was then cut
  off by the run clock. Claim-time sizing would have spread the probe over
  smaller tasks; streaming would have started templates on the first
  finished hosts.
- **Two politeness definitions.** 32 of 34 requeues in 30 days were sensors
  handing work back ("its hosts are busy on this sensor") because the
  platform and the SDK computed host keys differently. One key function in
  the SDK core, used by both, ends that loop (W1).

## 2. Decisions

| # | Question | Decision |
|---|---|---|
| P1 | Is the pool the direction? | Yes. It completes RFC-030 Phase 2: the pool holds items, the wire carries claim-time tasks |
| P2 | Item grain | One typed unit (RFC-088) × step; ranges stay pieces (≤ /24, ≤ /120), never single addresses |
| P3 | Batching | At claim, within one lane, sized by learned budgets and guided self-scheduling; size 1 for single-target tools and long tools |
| P4 | Matching | Lanes (constraint signatures) are the unit of eligibility, fairness and explanation; the claim matches a sensor against lanes, not items |
| P5 | Fairness | Class → tenant (shared pool) → run → step (downstream first), start-time fair queuing on lane rows, ageing |
| P6 | Urgent work | Cooperative yield; a running item is never killed for priority |
| P7 | Pipelines | Stream per task by default; a barrier only when the stage declares one |
| P8 | Politeness | One key function in the CTIS contract (ctis), used by both sides; no cross-tenant exclusivity |
| P9 | Dedup across scans | Later, opt-in, tenant-local, never for verify or credentialed runs |
| P10 | Offline sensors | Later, bounded expeditions on key-bound signed-job sensors only |

## 3. Today

### 3.1 Commands are the queue

One table, `commands`, is both the queue and the wire unit. A step's chunks
are commands that share `scan_run_step_id`. There is no run id column (only
`payload->>'scan_run_id'`), no tool or capability column (payload
`scanner`, `preferred_tool`, `required_capabilities`, `required_features`)
and no chunk table. Later columns add `host_keys`, `dispatch_gate`, window
hold columns and lease columns (`lease_epoch`, `lease_expires_at`,
`refused_by`, `refusals`).

### 3.2 Claim

`GetPendingForSensor` selects pending, due, host-free commands of the
sensor's tenant that are pinned to it or unpinned, in its zones, for a tool
it runs, not refused by it, with the features and capabilities it reports.
`fairPendingQuery` orders up to 1 000 candidates by priority class with
ageing (+1 class per 30 min, never into critical), then round-robin across
runs. `ClaimManyForSensor` takes advisory locks per host key, drops
candidates that share hosts within the batch and claims with
`FOR UPDATE SKIP LOCKED`, bumping `lease_epoch`. The service caps scans at
the sensor's free slots, applies local policy, re-checks scope (narrowing
the payload or failing `SCOPE_CHANGED`), window and program holds, then
signs each claimed command.

**Platform sensors.** The SQL function `get_next_platform_job` (per-tenant
fairness, host keys since migration `platform_jobs_host_keys`) and its Go
wrapper `CommandRepository.GetNextPlatformJob` have **no caller** outside
tests. A tenant-less platform sensor is refused on the v2 command routes
(`sensorForV2` answers scope-denied when the sensor has no tenant), and v3
forwards to the same handler, so it cannot claim anything today. A platform
sensor registered under a tenant claims through the ordinary tenant path
above, like any tenant sensor. Commands marked `is_platform_job` are
created (zones, trigger and step dispatch), reprioritised, recovered and
expired by controllers, but nothing hands them to a platform sensor; the
tenant claim predicate does not check `is_platform_job`, so an unpinned one
can be taken by that tenant's own eligible sensor. The shared platform pool
is therefore built new here (W11), and the dead function is removed with
the old claim path (W12).

> **Update (RFC-100 S5).** The shared-sensor side of W11 shipped: shared
> sensors claim shared jobs through their own claim path (fair share across
> organizations, the organization's concurrency limit, the same leases and
> host keys), and `get_next_platform_job` with its Go wrapper is removed
> ([sensors.md](../architecture/sensors.md#the-shared-claim-path)). Lanes,
> tenant pending caps and the sensor breaker of W11 remain.

### 3.3 Chunking, politeness, chaining

Steps are cut **at step start**: one command per chunk, sizes per stage
(subdomains 50, dns 200, ports 50 and ≤ 1 024 addresses, http 200,
templates 25, dast 10, …), for list tools only. Ranges are pieces of at most
/24 (IPv4) or /120 (IPv6). An active stage's chunk holds per-host keys
(`in:`/`net:` bucket keys for addresses and ranges) while it runs.

A step is runnable only when every dependency finished; a chunked step
settles after its last chunk; at most 3 steps run in parallel. Nothing
streams between steps.

### 3.4 Observability

`command_claims_total{mode}` counted only `claim` (by id), never `claim_n`
(the poll); `command_leases_expired_total`; `sensor_job_signing_total`.
There was no claim latency, queue depth or wait reason metric. Per task,
`placement.go` explains why a command waits (E1).

## 4. Use cases that shaped the design

| Use case | What the pool needs |
|---|---|
| Internet vs internal sensors | lane carries network, internet need, IP family; self-narrowing removes a sensor from a lane (RFC-089) |
| Confined vs unconfined tools | lane `required_features` |
| Different tools installed | lane `tool`; a missing tool makes the lane ineligible with a reason |
| Overlapping private ranges at two sites | network id in the lane and in politeness and dedup keys |
| Pinned targets | a lane per pinned sensor; never stolen; offline pin waits with a reason |
| Multiple vantage points | one item per vantage, lanes differ by vantage, never coalesced |
| Urgent retest | `verify` class lane taken first; cooperative yield when no slot frees |
| Fairness across tenants, scans, steps | hierarchical fair queuing on lane rows; ageing |
| Per-host politeness | per-item keys from one shared function, in-flight count per key |
| Windows and freezes | item `not_before`; a lane is closed while its window is closed |
| Sensors join, leave, slow down | tasks shrink near the end; lease expiry returns unfinished items; slow sensors get smaller tasks and skip a run's tail |
| One host with many URLs | items share one key, are grouped into one task, serialised by `per_host` |
| Streaming pipeline | each task's ingest inserts successor items |
| Reach failure | per-item reach class adds the sensor to the item's avoid list and reroutes |
| Stall, cancel, partial, resume | item states; only unfinished items return |
| 100k-target bursts, one /16 | bulk insert, pieces as items with weight, per-tenant pending quota |
| Long tools (DAST, full-port) | task of one item; a per-sensor share of slots for long tasks |
| Shared platform pool | tenant level in fair queuing, per-tenant leased cap, pending quota, redacted explanations |
| Offline sensor | bounded "expedition" claim with a long, ledger-bounded signed expiry |
| Observability | depth, oldest wait and reasons per lane; ETA from learned durations |

None of these needs the platform to push to a chosen sensor. Every one is
served by "eligible lanes + server-sized claim + item-level settlement".

## 5. Design

### 5.1 Vocabulary

- **Item**: one unit (RFC-088) for one step of one run. The unit of
  planning, politeness, retry and progress.
- **Lane**: the items of one run step that share every hard constraint
  (tenant, run, step, capability, tool, settings digest, zone, network,
  vantage, internet need, IP family, required features, tier, pin, class).
  The unit of eligibility, fairness bookkeeping and explanation.
- **Task**: what a sensor executes: n items of one lane, one command row,
  one signed statement, one lease. The wire stays the command (protocols
  v1, v2 and v3 unchanged).

### 5.2 Data model (one add-only migration)

```sql
CREATE TABLE pool_lanes (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  run_id uuid NOT NULL,                   -- composite FK (tenant_id, run_id)
  step_run_id uuid NOT NULL,
  capability text NOT NULL, tool text,    -- NULL = any tool of the capability
  settings_digest text NOT NULL,          -- tool settings + web scope + limits (signed)
  zone_id uuid, network_id uuid, vantage text, requires_internet boolean, ip_family smallint,
  required_features text[] NOT NULL DEFAULT '{}',
  tier smallint NOT NULL, pinned_sensor_id uuid, platform boolean NOT NULL,
  class smallint NOT NULL,                -- verify .. background
  state text NOT NULL,                    -- waiting_deps | open | held_window | closed
  pending_items integer NOT NULL DEFAULT 0, pending_weight bigint NOT NULL DEFAULT 0,
  leased_items integer NOT NULL DEFAULT 0, oldest_pending_at timestamptz,
  vt double precision NOT NULL DEFAULT 0, -- fair-share virtual time
  wait_reason jsonb,                      -- last eligibility summary: counts and codes only
  created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL
);
CREATE INDEX pool_lanes_open ON pool_lanes (tenant_id, class, vt)
  WHERE state = 'open' AND pending_items > 0;
CREATE INDEX pool_lanes_platform_open ON pool_lanes (class, tenant_id, vt)
  WHERE platform AND state = 'open' AND pending_items > 0;

CREATE TABLE work_items (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL, lane_id uuid NOT NULL,   -- composite FK (tenant_id, lane_id)
  run_id uuid NOT NULL, step_run_id uuid NOT NULL,
  unit_kind smallint NOT NULL,            -- name | addr | range | url | service
  unit_key text NOT NULL,                 -- canonical, ≤ 2 KiB
  weight integer NOT NULL,                -- 1, or the address count of a range piece
  host_keys text[] NOT NULL,              -- ctis/politeness, network-scoped
  ord bigint NOT NULL,                    -- planner order (hop, rotation, criticality)
  class smallint NOT NULL,
  state smallint NOT NULL,                -- pending | leased | done | failed | skipped | canceled | held_offline | following
  not_before timestamptz,
  attempt smallint NOT NULL DEFAULT 0, max_attempts smallint NOT NULL DEFAULT 3,
  avoid_sensors uuid[] NOT NULL DEFAULT '{}',   -- ≤ 16
  task_id uuid, lease_epoch integer,
  parent_item_id bigint, hop smallint NOT NULL DEFAULT 0,
  outcome smallint, reason text,
  coalesce_key bytea, leader_item_id bigint,
  created_at timestamptz NOT NULL, settled_at timestamptz,
  UNIQUE (step_run_id, unit_key)          -- an output reaches a step once
) WITH (fillfactor = 80);
CREATE INDEX work_items_claim ON work_items (lane_id, class, ord) WHERE state = 0;
CREATE INDEX work_items_task  ON work_items (task_id) WHERE state = 1;
CREATE INDEX work_items_run   ON work_items (run_id, step_run_id, state);

CREATE TABLE pool_host_inflight (
  tenant_id uuid NOT NULL, host_key text NOT NULL, leased integer NOT NULL,
  PRIMARY KEY (tenant_id, host_key));

ALTER TABLE commands ADD COLUMN lane_id uuid, ADD COLUMN item_count integer,
  ADD COLUMN budget_seconds integer;
```

- **Size.** A /16 is 256 piece items, not 65 536 rows; RFC-030's 200k items
  per run bounds names. Settled items of a settled run are compacted after
  14 days into the run's coverage summary and unfinished targets, then
  deleted; the claim index holds pending rows only.
- **Lane counters** change in the same transaction as item states; they only
  order and explain, the item rows are the truth, and a reaper reconciles.
- **`pool_host_inflight`** replaces the scan over active commands'
  `host_keys`: incremented at lease, decremented at settle or expiry in the
  same transaction, recomputed from leased items every minute.

### 5.3 Planning (producer)

At run start the planner (dispatch gate + RFC-088 splitting + the per-stage
kind gate) emits units per step and bulk-inserts them, grouped into lanes by
constraint signature. Steps fed by seeds open at once; chained steps open in
`waiting_deps` and receive items by streaming (§5.7). A tenant's pending
items are capped (tenant setting ≤ platform maximum); a run over the cap
waits `POOL_QUOTA` with the reason shown; nothing is dropped. The planner
never resolves eligibility to a sensor; a lane no sensor could take gets
today's refusals (`NO_SENSOR_FOR_TOOL`, `NO_ZONE_COVERAGE`,
`NETWORK_AMBIGUOUS`, …) or waits with a reason.

### 5.4 Claim (consumer)

```
claim(sensor s, k requested):
  k ← min(k, free_slots(s))                 # server truth, long-tool share
  E ← eligible_lanes(s)                     # SQL over pool_lanes: s's tenant (or the platform pool),
                                            # zone, network/vantage/internet/family vs s's report,
                                            # tool, features, tier ≤ grant, pin ∈ {NULL, s}, open;
                                            # then the Go gate per LANE (grant, trust, posture,
                                            # local-policy summary), cached by (s.config digest, lane)
  while k > 0 and E not empty:
    L ← pick(E)                             # class → tenant (platform) → run → step: least vt
    n ← size(L, s)                          # §5.5
    items ← pending items of L, due, s ∉ avoid_sensors,
            ORDER BY class, ord LIMIT 4n FOR UPDATE SKIP LOCKED
    items ← politeness_filter(items, n)     # in-flight < per_host; prefer items whose keys repeat
    if items empty: mark L host-blocked for this poll; continue
    scope_recheck(items)                    # per unit; a dropped unit is skipped(scope_changed)
    task ← INSERT command(lane, items, budget, lease)
    UPDATE items SET state = leased, task_id, lease_epoch; counters; vt += cost/weight
    k ← k − 1
  sign each task (units, intersecting exclusions, grant kind, settings digest, budgets, limits, epoch)
```

- One transaction per task; `SKIP LOCKED` gives concurrent claims of a lane
  disjoint items.
- Lane selection is an index scan over the open lanes of one tenant (or the
  platform index): O(open lanes), expected a few thousand at most on a
  large shared deployment. The item pick is O(log N + 4n).
- Target before the default flips: p95 claim < 50 ms at 100 polls/s with
  1M pending items and 2 000 open lanes (load test in W5).
- The eligibility cache only orders and explains. **The lane predicate is
  evaluated again inside the claim transaction** against the current sensor
  row. The same evaluation feeds the per-task "why it waits" explanation (one
  code path; the existing agreement test is extended to lanes).

### 5.5 Sizing

```
T_tgt(tool, s) = clamp(learned per-target p95 for (tenant, tool) × speed(s), floor, ceiling)
n_budget       = ⌊(τ − overhead) × concurrency / T_tgt⌋      τ = task budget target (300 s)
n_gss          = ⌈remaining weight / (2 × live sensors)⌉       guided self-scheduling
n              = clamp(min(n_budget, n_gss, n_max(tool)), 1, …)  in weight units
B              = overhead + ⌈n / concurrency⌉ × T_tgt          the task's budget, sent with it
```

`speed(s)` is a per-sensor factor (moving average of actual over expected,
clamped 0.25–4). A sensor more than 1.5× slower than the best live one does
not claim from a lane whose remaining weight is under two tasks per fast
slot. No task is cut when the run's deadline leaves less than
`overhead + T_tgt`; the items roll over. Tasks with `B > 30 min` may hold at
most half a sensor's slots (at least one stays free for short work).

### 5.6 Fairness and priority

Classes `verify > interactive > scheduled > background`, ageing +1 class
per 30 min (never into `verify`); today's `commands.priority` maps 1:1.
Within a class, start-time fair queuing by virtual time: tenant (shared pool
only), then run (weight 4 interactive, 1 otherwise), then step, downstream
first, so a pipeline drains before it widens. `vt` lives on the lane row, so
every API replica sees the same order. In the shared pool no tenant holds
more than half the platform's slots while others wait; alone it may use all.

**Cooperative yield** replaces preemption: when a `verify` item has waited
more than 60 s and no eligible slot is free, the platform asks the eligible
sensor holding the lowest-class task with unstarted items to yield
(heartbeat action). The SDK stops starting new targets, finishes and reports
the running ones and releases the rest without an attempt. The same action
drives rebalancing when a sensor joins, window closing and drain.

### 5.7 Streaming between steps

On each task's ingest commit the hop router takes that task's outputs,
passes them through the one target gate (per hop, kind gate,
resolve-before-active, wildcard filtering) and inserts successor items with
`ON CONFLICT (step_run_id, unit_key) DO NOTHING` and `parent_item_id`. A
successor lane opens as soon as it has items and its step may start. **A
step completes** when every predecessor step completed and its lane has no
pending or leased item. The 3-parallel-steps cap becomes a per-run cap on
leased tasks and pending items per step (back-pressure: producers are not
claimed while a consumer lane is over its buffer). A stage that needs the
full set declares `input: barrier`; the default is stream. Seeds still reach
each step directly, so streaming changes timing, not what is scanned.

### 5.8 Settlement

| Event | Items |
|---|---|
| task completes | items with a per-target outcome → `done` (or `failed` with a reach class); items without one are unfinished |
| per-item `no_route` / `blocked` / `dns` | `pending`, the sensor added to `avoid_sensors`, attempt + 1; no eligible sensor left ⇒ `failed TARGET_UNREACHABLE` |
| local-policy refusal | the sensor added to `avoid_sensors` (lane-level refusal recorded for the explanation) |
| tool crash | whole task `pending`, attempt + 1; an item failing on two sensors is isolated and `failed` after `max_attempts` |
| lease expiry | unfinished items `pending`, attempt + 1, front of the lane |
| stall or overrun | the task is cancelled; done items kept; unfinished `pending` once, then rolled over |
| yield or release | unstarted items `pending`, no attempt |
| run cancel | pending items `canceled`; leased tasks get the cancel action |
| run deadline | pending items unfinished; the rollover plans them first |

Per-item outcomes need the task to report which targets finished
(indexes into the task's target list, bounded and monotonic, next to the
done/total progress) and a reach class per target. Until then a completed
task settles all its items `done` and a failed or expired one returns all of
them: today's behaviour, no regression.

### 5.9 Politeness

One key function lives in the CTIS contract,
`github.com/openctemio/ctis/politeness` (standard library only), which the
platform and the sensor SDK both import (the platform never depends on the
SDK):

- a name, and the host of a URL or a service: the lower-case name without
  a trailing dot;
- an address: canonical form and the `in:` marker of its /24 (/120) bucket;
- a range: the `net:` key of every bucket it covers;
- a repository clone URL or scp form: `host/owner`; a local path: itself;
- with a network context (RFC-089), the keys of private, shared, loopback
  and link-local addresses and of names end in `#<network>`; public
  addresses are never scoped, so a public host is one host whichever network
  the work came from.

An address conflicts with a range scan of its bucket, either way round; two
addresses of one bucket do not. The platform computes the keys with this
function, holds them while a task runs and **sends them with the task**
(`host_keys`, an empty list for a passive stage); the SDK admits the task
under exactly those keys with the same conflict relation and computes them
itself (same function) only for a task without them. Local policy may still
be stricter (it can only refuse). Per-host request rates go in the task's
limits, a zone's `max_rps` is split across its leased tasks, and the sensor
backs off adaptively (RFC-074).

No cross-tenant exclusivity in the shared pool: making one tenant wait for
another tenant's work on a third-party host would leak that work through the
wait. A per-platform-sensor egress ceiling per destination (RFC-074) covers
it.

### 5.10 Dedup across scans (later, opt-in)

Within one tenant only. Coalescing key = hash(tenant, network, vantage,
unit, capability, tool, settings digest, scope and exclusion digest, tier).
A new item whose key matches a `pending` or `leased` item of another run
follows that leader and settles with "covered by run X"; the run's coverage
counts it. Never for `verify`, credentialed or manual runs.

### 5.11 Offline expeditions (later)

A tenant-owned, key-bound sensor with signed jobs and the grant flag
`offline_claims` may claim in offline mode: up to N items (tenant setting),
one task, a signed expiry of up to 7 days (platform maximum, allowed by the
signer only for this mode and within the ledger scope). The items are
`held_offline` and never stolen until expiry; results are accepted until
expiry plus grace, bound to the task and its epoch; on expiry the items
return with `offline_expired`.

### 5.12 Observability

Metrics carry no tenant, sensor or run label (RFC-046 decision B9): the
tenant dimension is reported as aggregates (how many tenants wait, the
largest single tenant's share), never as identities.

| Metric | Meaning | Step |
|---|---|---|
| `command_claim_duration_seconds{mode}` | how long a claim takes (`claim` by id, `claim_n` by the poll), histogram | W2 |
| `command_claims_total{mode}` | `claim_n` now counted, one per command the poll claims | W2 (fix) |
| `command_claim_wait_seconds{class}` | how long a command waited from creation to its claim, histogram | W2 |
| `command_claim_skipped_total{reason}` | candidates a poll did not hand out, by reason (`no_slot`, `local_policy`, `scope_changed`, `window_hold`, `program_hold`, `taken`) | W2 |
| `openctem_command_queue_depth{stage,tool,class,wait}` | pending commands by stage, tool, class and why they wait (`ready`, `host_busy`, `scheduled`) | W2 |
| `openctem_command_queue_tenants` | tenants with at least one pending command | W2 |
| `openctem_command_queue_top_tenant_pending` | pending commands of the tenant with the most (fairness signal, no identity) | W2 |
| `pool_items{state,class}`, `pool_lanes_open{class}`, `pool_task_items{tool}`, `pool_handbacks_total{reason}`, `pool_yield_total{reason}`, `pool_estimate_error_ratio{tool}`, `pool_host_blocked_total` | the pool itself | W3–W9 |

Per lane: depth, oldest wait, eligible and busy sensor counts, top blocking
reasons with fixes, ETA = pending weight × T_tgt ÷ eligible concurrency (as a
range). Per run: items by state per step, streaming flow, unfinished list.

### 5.13 UI

- **Run page → Work panel**: per step a bar of items (waiting, running,
  done, failed, skipped), arrows for streaming, an ETA range, and for waiting
  items the lane's reason ("3 sensors can run this; all busy", "no sensor on
  network Site B", "window closed until 22:00"). Actions: cancel, scan
  unfinished, raise priority (permission-gated).
- **Scans → Queue**: depth by class, oldest wait, blocked lanes with
  reasons, sensor utilisation; the platform pool is one "Platform scanning"
  row with no node data.
- **Admin console → Platform pool**: depth and in-flight per tenant as
  aggregates, quota hits, claim latency; no item content.
- Every string through `t()` in en and vi.

## 6. Security

| Threat | Control |
|---|---|
| A sensor claims or sees items outside its eligibility | lane predicates are authorization, evaluated again in the claim transaction against the current sensor row; the Go gate (grant, trust, posture, local-policy summary) runs per lane at claim; item content only ever leaves inside a task to the claiming sensor; scope re-check per unit at claim; the signer checks units ⊆ ledger scope − exclusions; the SDK verifies and applies local policy (it can only refuse) |
| Signed per claim, with exclusions | the statement lists the units (ranges as pieces), the exclusions that intersect them, grant kind, settings digest, budgets, lease epoch, ≤ 1 h expiry (offline mode the only, ledger-bounded exception); ingest drops results outside the task's units |
| Pool metadata leaks across tenants | every pool table tenant-scoped with composite FKs; shared-pool lane selection returns lane ids only; a task holds one tenant's items; explanations and queue views name only the caller's sensors, platform sensors redacted; no cross-tenant politeness waits; platform-wide metrics have no tenant label |
| A malicious sensor drains the pool | tasks are server-sized and bounded; claims bounded by server-side free slots; a per-sensor claim rate; a tenant sensor sees only its tenant's lanes |
| A malicious sensor starves others | per-sensor breaker: repeated lease expiries, stalls or empty completions pause its claims, notify the admin and put it in the affected items' avoid lists |
| Fake progress or completion | progress only for tasks it holds under the current epoch, monotonic and bounded; caps still apply; `reached = 0` ⇒ `TARGET_UNREACHABLE`, never "clean"; yield anomalies against peers on the same lane flagged |
| Fake reach to pull work | reach and learned evidence only remove or reorder lanes, never add one |
| Coalescing returns results of a different scope | the key includes scope, exclusion and settings digests and the tier; tenant-local; never for verify or credentialed runs |
| Offline replay or overreach | key-bound sensors with pinned roots only; ledger bounds; sequence and nonce; items exclusive until expiry; results bound to the task |
| Pool denial of service by a huge plan | pieces, 200k items per run, tenant pending quota, bounded bulk inserts, partial claim index |
| Politeness keys sent with a task | platform-authored at creation, inside the signed payload; the SDK bounds them (≤ 500 keys of ≤ 512 bytes); they only hold work back, never widen what a sensor may run |

## 7. How it absorbs related work

- **RFC-088.** Units are the item kinds; weight chunks become the claim-time
  weight budget; pieces are items; live-hosts-first discovery is the first
  streaming producer; per-task exclusions and the out-of-unit drop bind to
  the task's items; single-scanner scans plan items too; coverage rotation
  becomes item order.
- **RFC-089.** Network, vantage, internet need and IP family are lane
  columns; self-narrowing is part of lane eligibility; per-item reach
  outcomes drive avoid lists and reroute; vantage `both` is two lanes; a
  task never mixes networks by construction.
- **Run liveness and budgets.** Learned per-target budgets size tasks; the
  task budget is computed at claim; progress with finished targets settles
  items; stall and overrun requeue only unfinished items; the dispatch guard
  becomes claim-time admission; the ETA comes from the same statistics.

Two interface choices are asked of that work: progress reports finished
targets as indexes into the task's target list (bounded, monotonic) with a
reach class per target; and single-scanner chunking goes through the
workflow step path (one producer to move onto the pool), with learned
durations keyed by (tenant, tool) behind an exported budget lookup.

## 8. Migration from today's commands

1. **Shadow** (W3): the planner writes items and lanes next to the commands
   it already creates (`task_id` = the pre-cut command). Metrics and the
   Work panel read items; the claim is unchanged.
2. **Per-tenant flag** (W5, `scan_pool`): a flagged tenant's new runs write
   items only and commands are created at claim; old runs drain on the old
   path. Both paths share `pool_host_inflight`.
3. **Default on** after the load test and two weeks of estimate error and
   claim latency on live. Sensors on any protocol keep working: a task is a
   command.
4. **Retire** (W12): step-start chunking, the scan path of
   `fairPendingQuery`, trigger-time single-scanner fan-out and the unused
   `get_next_platform_job` are removed. Non-scan commands stay plain
   commands.

## 9. Plan

**SEC** marks a security-sensitive step.

| # | Repo | Step | Depends | SEC |
|---|---|---|---|---|
| W0 | api docs | This RFC; RFC-030 and RFC-046 amendment notes; architecture; index | — | — |
| W1 | ctis → sdk-go → api → sensor | One politeness key function (`ctis/politeness`, in the contract repository); api delegates and sends the keys it holds with each chunk; the SDK admits under those keys with the same conflict relation; agreement test on a table of target pairs | — | **SEC** |
| W2 | api | Claim latency, queue depth by class and by stage/tool, wait-reason counts, claim wait seconds; fix `claim_n` | — | — |
| W3 | api | Work items and lanes in shadow: migration, planner writes, counters, compaction, run `work` summary; cross-tenant and out-of-scope negative tests | W0 | **SEC** |
| W4 | api | Settle items from task results (finished indexes + reach), whole-task fallback | W3, SDK progress | — |
| W5 | api | Claim from the pool behind a per-tenant flag: lane eligibility SQL, Go gate per lane with cache, lane fair queuing, claim-time cut, command at claim, scope re-check per unit, signing with units; lane explanations; load test | W1, W3 | **SEC** |
| W6 | api | Learned task sizing: budgets × sensor speed, guided self-scheduling, tail rule, claim-time admission, long-tool slot share | W5, learned durations | — |
| W7 | api | Item retries and reroute: avoid lists, poison isolation per item, stall/overrun requeue of unfinished items only | W4, W5 | **SEC** |
| W8 | api | Stream outputs into the next step: hop router per task ingest, dedup, step completion rule, downstream-first order, per-run buffers, `input: barrier` | W5 | — |
| W9 | sdk-go → api | Yield: heartbeat action; the SDK releases unstarted targets with a done list; used for verify waits, joins, window close, drain | W4, W5 | **SEC** |
| W10 | web (+ api) | Run Work panel, Scans → Queue, why waiting, ETA (en + vi) | W2, W3, W5 | — |
| W11 | api | Shared-pool quotas and a sensor breaker: tenant pending and leased caps, per-sensor claim rate, platform pool lanes (replace the unused platform queue function; the shared-sensor side is RFC-100 S5), admin aggregates | W5 | **SEC** |
| W12 | api | Every scan plans items: single-scanner scans, retests and validations (class `verify`) on the pool; remove step-start chunking, the scan claim path and `get_next_platform_job`; default on | W5–W8 soak | — |
| W13 | api | Coalesce identical work across runs (opt-in, tenant-local) | W12 | **SEC** |
| W14 | api + sdk-go + sensor | Offline expeditions: grant flag, signer TTL exception within the ledger, `held_offline`, outbox binding | W12 | **SEC** |
| W15 | api | Soft affinity with delay scheduling for content packs and repository mirrors, off by default | W5 | — |

W0, W1 and W2 are independent and land first. W3 does not depend on the
in-flight budget and progress work; W4 and W5 follow the SDK progress and
task budgets; W6 and W7 follow learned durations.

## 10. Risks

| Risk | Mitigation |
|---|---|
| The claim hot path regresses latency or locks | lanes bound the search; partial indexes; per-tenant flag; load-test gate in W5; old path kept until W12 |
| Lane counter drift | same-transaction updates and a reconciling reaper; counters only order and explain |
| Write amplification | pieces, fillfactor 80, compaction after runs settle |
| Per-item settlement wrong | finished indexes from the SDK, a reach class required for `done`, whole-task fallback only when absent; ingest output binding |
| Streaming floods a deep step | per-hop gate, fan-out cap, per-step buffers, per-run budgets |
| Yield wastes work | only unstarted targets are released; yield is rate-limited per task |
| Two paths disagree on politeness during the transition | shared `pool_host_inflight` and the single key function (W1) |
| Steps overlap in time | the Work panel shows it; seeds and gates are unchanged, so what is scanned is unchanged |

## 11. Not built

- No push or plan-time assignment; no speculative duplicate execution; no
  hard preemption.
- No cross-tenant work sharing, coalescing or politeness exclusivity.
- No per-address items: ranges stay pieces and the SDK iterates addresses.
- No provider-owned sensors serving many tenants until an organization
  model for them exists (a lane can accept a "served tenants" set then).
- No spot re-verification until a malicious-sensor signal is observed.
