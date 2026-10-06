# RFC-035 — Sensor control plane under load: heartbeats that survive the scans they supervise

> Status: **Accepted** (owner decisions 2026-10-02, §6.1; proposed in api#727).
> - Phase 1 (SDK, no decision needed) is merged: sdk-go#113.
> - D2 (the B1 fix) is in api#746.
> - D1, D3, D5 and D6 are in implementation; D4 was declined and D7 deferred (§6.1).
> Scope: sdk-go + api + sensor (`openctemio/sensor`, local checkout `agent`) + ui.
> Builds on [RFC-023](RFC-023-scan-zones-and-scanners.md) §9.2a (heartbeat
> doorbell), [RFC-029](RFC-029-sensor-protocol-v2-and-sdk-stability.md)
> (protocol v2), [RFC-030](RFC-030-scan-work-distribution.md) (load report,
> slots, leases D6) and [RFC-033](RFC-033-sensor-manifest.md) (manifest, slim
> heartbeats). It coordinates with [RFC-034](RFC-034-sensor-network-egress.md) (sensor network egress): the
> heartbeat's own HTTP client takes its proxy from the same place as every
> other platform request.
>
> Owner's question (2026-10-02): "When a sensor scans, it usually eats
> resources, but meanwhile it must still heartbeat and talk to the platform.
> Think this mechanism through, research deeply, use many sources."

## 1. Answer in short

**A busy sensor must never look like a dead one, and a dead one must not
look busy.** We measured where today's design actually breaks. The answer
is not "CPU": a sensor whose scanners saturate every core still heartbeats on
time. The weak points are these:

- **Memory.** The kernel's OOM killer picks the process with the most
  memory. That can be the sensor itself, while it parses a large result.
  The sensor is PID 1 in its container, so the whole container dies, every
  running scan is lost, and the platform never re-queues them.
- **Slow work on the heartbeat path.** Every 10 minutes the heartbeat runs
  each tool's version check inline. The manifest exchange also runs inline.
  A failed heartbeat is retried 3 times, with 30 s timeouts.
- **The platform's own thresholds.** The platform marks a sensor offline
  after 90 s, which is 1.5 × the SDK's default interval. Under load it
  advises a 120 s interval, longer than its own offline mark, so a sensor
  that follows the advice is declared offline (bug B1, reproduced).

The fix has four layers:

| Layer | Today | Proposal |
|---|---|---|
| **Control channel** (SDK) | Heartbeats share the data plane's HTTP client. 3 retries × 30 s on failure. Version probes and the manifest exchange run inline. | Own HTTP client and connection pool. 15 s timeout, at most 1 retry, the next heartbeat after ~10 s. Probes refresh in the background; the manifest exchange is bounded. **Phase 1.** |
| **Headroom and isolation** (sensor host) | Slots use all the memory the sensor sees. Scanners run at the sensor's own CPU, I/O and OOM priority. | Slots leave memory for the sensor (like kubelet `system-reserved`). Scanners run at nice +10, best-effort I/O 7, `oom_score_adj` 500: the kernel kills a scanner, not the sensor. **Phase 1.** A per-job cgroup with `memory.high` when delegation exists: **Phase 3.** |
| **Observability** | The platform sees only the arrival time. | Every heartbeat carries `control`: interval, gap, lag (CPU wait), build time, RTT, failures. **SDK in Phase 1**; stored, shown and alerted on in **Phase 2**. |
| **Platform tolerance** (api) | Fixed 90 s → `offline`, with `stale` effectively unused (B2). The 120 s "loaded" advice exceeds it (B1). | A per-sensor deadline from the interval the platform itself advised. A suspicion ladder: online → late → stale → offline. Advice never above the deadline. No conviction while the platform itself is slow (Lifeguard). Leases (RFC-030 D6) re-queue only after the sensor is past the deadline. **Owner decisions D1–D6.** |

## 2. Current state (verified on api `develop` d832bae84, sdk-go `main` 8324670, sensor `main` 679e974)

### 2.1 Sensor side (sdk-go)

**One goroutine, one serial path.** `core.BaseSensor.heartbeatLoop`
(`pkg/core/base_sensor.go:836`) arms a timer. When it fires,
`heartbeatOnce` (`:784`) runs these steps one after the other:

1. `withCapabilities`. The capability report comes from
   `ToolRegistry.CapabilityReport` (`pkg/core/tool_registry.go:402`). Once
   the probe TTL (`DefaultToolProbeTTL`, 10 min) has passed, it runs every
   tool's `IsInstalled` **under the registry lock and inside the heartbeat**:
   `nuclei -version`, `trivy --version`, `semgrep --version`. Each one has a
   30 s timeout (`DefaultToolProbeTimeout`).
2. The load snapshot. `CommandPoller.ReportStatus` → `resource.Manager.Snapshot`
   reads `/proc` and the cgroup files (cheap).
3. `syncManifest` (`:119`). The first time, and on change or request, it
   calls `PUT /api/v2/sensor/manifest`. On a `config_version` change it
   calls `GET /manifest`. Both use the client's retry policy (`MaxRetries`
   3).
4. The send. `client.sendHeartbeat` (`pkg/client/client.go:641`) →
   `doRequestFull(..., c.maxRetries)` (v1) or `v2JSON(..., c.maxRetries)`
   (v2). That means up to **4 attempts**. Each is bounded by the
   transport's 15 s response-header timeout and the client's 30 s timeout
   (`httpsec.NewAPIClient`), plus jittered backoff of 1–2, 2–4 and 4–8 s.
5. Only then is the timer re-armed. On success it uses the advised
   interval. **After a failure it uses the sensor's own `HeartbeatInterval`
   (default 60 s), not the 30 s the platform advised last** (B7).

**Worst case before the next heartbeat** = interval + probes (n × up to
30 s) + manifest (up to ~134 s) + send (up to ~134 s). The platform
convicts at 90 s.

**Shared HTTP client.** Heartbeats, polls, claims, uploads and the outbox
all use the one `*http.Client` from `httpsec.NewAPIClient`. That client is
HTTP/1.1 (a custom `DialContext` and `TLSClientConfig` turn HTTP/2 off), so
an upload takes a connection of its own. The pool is shared, though, and it
is unbounded only because `MaxConnsPerHost` is 0.

**Scanners are child processes** (`core.ExecuteScanner`, `StreamScanner`,
`BaseScanner.Scan`). `ConfigureScannerProcess` (`pkg/core/proc_group.go`)
puts each one in its own process group (killed as a group on cancel),
with `Pdeathsig`. Nothing changes their priority: they inherit the sensor's
nice 0, its I/O class and its `oom_score_adj`.

The sensor's own `internal/executor` (platform mode) and
`internal/content/exec.go` start tools with plain `exec.CommandContext`.
They get no process group and no priority.

**Slots** (`pkg/resource/manager.go`):
`min(cap, ⌊cpu/job_cpu⌋, ⌊(mem_available + active × job_mem)/job_mem⌋)`,
narrowed by an AIMD window. The window halves on an OOM kill or on CPU
throttling above 50 %, and on a job timeout. **No memory is kept for the
sensor itself.** The sensor buffers every scanner's whole stdout
(`captureOutput`) and parses it in memory, so it is the process whose
memory spikes at the end of every scan.

**SIGTERM** drains: no new claims, a drain grace, then the scans are
cancelled and released (`POST /commands/{id}/release`). The outbox keeps
undelivered results on disk.

### 2.2 Platform side (api)

| Mechanism | Where | Behaviour |
|---|---|---|
| Advised interval (doorbell) | `internal/app/sensor/doorbell.go:143`, `internal/config/config.go:213` | idle 30 s, busy 5 s (work pending), **loaded 120 s** when the doorbell query takes ≥ 250 ms; clamped to [5 s, ½ × `WORKER_HEARTBEAT_TIMEOUT` = 150 s] |
| Offline mark | `internal/infra/controller/sensor_health.go`, wired in `cmd/server/workers.go:219` | every 30 s: `health='offline'` when `last_seen_at < now − 90 s` (**hard-coded**); emits `sensor.offline` (severity high) to the notification outbox, an audit event and an activity event |
| Fleet state ladder | `pkg/domain/sensor/fleet_health.go:180` | online ≤ online window (3 × idle interval, ≥ 90 s); stale ≤ `WORKER_HEARTBEAT_TIMEOUT` (5 min) **unless `health='offline'`**; else offline |
| Work recovery | `internal/infra/controller/job_recovery.go`, SQL `recover_stuck_tenant_commands` (migration 000230) | `acknowledged` > 10 min → pending (whatever the sensor's health); `running` never; pending pinned to an offline sensor → unpinned (`ReleasePendingFromUnavailableSensors`); run timeout 1 h fails the rest |
| Dispatch | `scan_zone_repository.go:321,400`, `sensor_repository.go:621–679` | zone routing and sensor selection require `health='online'` |

There are no command leases yet. RFC-030 D6 specifies them as
`lease = 3 × heartbeat interval, clamped 60–300 s`, renewed by the
heartbeat's `running` list, with expiry re-queueing the chunk.

### 2.3 Defects found

| # | Defect | Evidence | Effect |
|---|---|---|---|
| B1 | The "loaded" advice (120 s) is longer than the offline mark (90 s). The doorbell clamps advice to ½ `WORKER_HEARTBEAT_TIMEOUT` (150 s), but the health controller convicts at a hard-coded 90 s. | `doorbell.go:86`, `workers.go:221`; reproduced in §3 | When the platform's DB is slow, **every sensor that follows the advice is marked offline once per cycle**. Each time it gets a `sensor.offline` notification (high), an audit event, an activity entry and its pinned work released, then it flips back online on the next heartbeat. Work moves at exactly the moment the platform is slowest. |
| B2 | The `stale` state is unreachable in practice. The controller writes `health='offline'` at 90 s; the ladder shows `stale` only while `health != 'offline'`. | `fleet_health.go:206`, `sensor_health.go:123` | The documented "stale until 5 min" lasts at most one controller tick (≤ 30 s). The first conviction is the final one. |
| B3 | The heartbeat retries a stale report 3 times, 15–30 s each. | `client.go:719`, `control_v2.go:130` | Behind a black-holed connection one heartbeat cycle took ~70 s of retries (measured), instead of trying a fresh heartbeat 10 s later. |
| B4 | Version probes run inline in the heartbeat every 10 min. | `tool_registry.go:417` | Under a saturated CPU the probes took 4.8 s (§3), and one hung tool can add up to 30 s. That latency is invisible because nothing measures it. |
| B5 | `running` commands of a sensor that died are never recovered. Only the run timeout (1 h) ends them. | `recover_stuck_tenant_commands` | An OOM-killed sensor's scans hang until the run fails (§3, memout). |
| B7 | After a failed heartbeat the SDK waits its own `HeartbeatInterval` (60 s), not the platform's last advice (30 s). | `base_sensor.go:819` (`next` is the configured interval on the error paths) | In the black-hole run the sensor came back 72 s after the platform did. |
| B6 | Scanners started by the sensor's platform mode and its content refresh bypass `ConfigureScannerProcess`. | `agent/internal/executor/*.go`, `internal/content/exec.go` | No group kill on cancel and (with Phase 1) no lowered priority. |

## 3. Measurements

### 3.1 Method

**Live (read only).** `sensor-docker-01` runs v0.6.4 with SDK v0.14.0 on a
4-core host with no container limits. Over 45 minutes the platform received
92 heartbeats:

- gaps p50 30.02 s, p99 31.27 s, max 31.93 s;
- server handling p50 9.7 ms;
- `sensor_events` has no offline transition for it.

Live never came near the threshold, but it was mostly idle in that window.
The 94 % CPU reading the owner saw was during a scan.

**Scratch platform.** Everything ran on one host, with nothing touching live
data:

- **API**: the binary live runs (api `5e93ef27e`) with its migrations, on its
  own Postgres 17 and Redis containers.
- **Sensor**: a load-test sensor built twice from the same code, against
  sdk-go `main` (**before**) and against the RFC-035 branch (**after**). It is
  sensorkit with the real nuclei, trivy and semgrep registrations, so the
  real version probes run, plus a "hog" scanner.
- **Load**: the hog's child processes burn CPU (`cpu-N-S`: N busy processes)
  or memory. They are started by the sensor exactly like a scanner, through
  `core.ExecuteScanner`.
- **Container**: each run is pinned to 2 cores (`--cpuset-cpus=2,3`) so live
  keeps the other two.
- **What was recorded**:
  - every heartbeat's arrival time at the API (server-side gaps);
  - the sensor's `health` in the DB every 3 s;
  - `sensor_events`, command outcomes, cgroup `memory.events`;
  - each process's `oom_score_adj` and nice value;
  - for the after runs, the sensor's own `control` block, logged by a
    pass-through proxy.

### 3.2 Results

| Scenario | Load | Before (sdk-go main) | After (RFC-035 Phase 1) |
|---|---|---|---|
| **cpu**: 2 cores, no quota, 11 min | 2 jobs × 6 busy processes = 12 per core, sensor CPU 200 % | 129 beats, busy gaps p50 5.01 s / p99 5.04 s / **max 9.03 s**. The 9 s gap is the 10-minute **inline version probe** (B4). Never stale. | 130 beats, busy gaps p50 5.02 s / p99 5.05 s / **max 5.07 s**: the probe runs in the background. `control`: lag ≤ 6 ms, RTT p50 18 ms. Never stale. |
| version probes under that load (`nuclei`+`trivy`+`semgrep --version`, run at nice 0 like the sensor) | | idle 1.06 s → **4.81 s** under load (semgrep alone 4.25 s) | **1.26 s**: the scanners run at nice 10, so work at the sensor's priority stays fast |
| **quota**: `--cpus=1` on 2 cores | 6 busy processes, CFS throttling | busy gaps max 5.08 s, never stale | busy gaps max 5.08 s, `control` lag ≤ 54 ms, never stale |
| **mem**: `--memory=768m` | 3 jobs that each grow to 300 MiB | no OOM: the memory-aware slots ran one job at a time (`capacity_changed`) | the same, with 256 MiB reserved for the sensor |
| **OOM order**: 600 MiB container; the sensor (PID 1) holds 260 MiB and then parses (+120 MiB); 2 scanners of 150 MiB each (fork+exec, like the Go sensor) | memory limit hit | **the sensor is killed**: container exit 137, every scan lost | scanners at `oom_score_adj` 500: **a scanner is killed, the sensor survives** |
| **black hole**: the platform stops answering heartbeats for 75 s (connection held), then recovers | | 4 attempts × 15 s (transport header timeout) + backoff, then the SDK's **own 60 s interval** instead of the advised 30 s. Back **72 s after recovery**; gap **159.6 s** → **marked offline** | 2 attempts × 15 s, next try after 10 s. Back **26 s after recovery**; gap 113.7 s. Not marked offline this time, which depends on the controller tick; §5.6 removes that dependence. `control.failures` = 2 on the first heartbeat back. |
| **platform under load**: doorbell query treated as slow (`SENSOR_HEARTBEAT_SLOW_QUERY=1ns`) | sensor idle | The platform advises 120 s and the sensor obeys. The health controller marks it **offline every cycle** (13:20:59 offline, 13:21:03 online, 13:22:57 offline, …): 2 `offline` + 2 `online` events in 6 min, each a `sensor.offline` notification (**B1**). | unchanged: a platform-side defect (D2) |

Process priorities seen inside the after container:

```
1   adj=0   nice=0  /harness/sensor
105 adj=500 nice=10 python3 /harness/hog.py /workspace/cpu-6-300   (and its 5 forked children, the same)
```

### 3.3 What the numbers say

1. **CPU contention is not what kills heartbeats.**
   - Measured: 12 runnable processes per core, and CFS bandwidth throttling
     at 1 core, delayed a heartbeat by at most 54 ms.
   - Why: CFS/EEVDF schedule a sleeping, rarely runnable goroutine almost at
     once, and Go's GOMAXPROCS follows the cgroup quota.
   - The owner's 94 % CPU reading is normal and harmless for the control
     plane.
2. **What delays heartbeats is work done on the heartbeat path**: inline
   probes (+4 s here, up to 30 s per tool), retries with long timeouts
   (B3), and falling back to the SDK's own 60 s interval after a failure.
3. **Memory is the real danger, and the SDK's slots already avoid the naive
   overcommit.** What is left is the sensor's own spike when it buffers and
   parses a result. With equal OOM scores, that spike makes the sensor the
   kernel's victim, and with it the container and every scan.
4. **The platform convicts busy sensors by its own inconsistency** (B1, B2),
   not because of anything the sensor did.
5. **No job was re-queued spuriously** in any run, because today nothing
   re-queues `running` work. That is also why the scans of a dead sensor
   hang until the run timeout (B5). Leases (§5.7) must add re-queueing
   without adding spurious re-queues.

## 4. Research: proven techniques

Every source below was fetched and checked. The "[n]" numbers point to §9.

| System | What it does | What we take |
|---|---|---|
| **Kubernetes node heartbeats** (KEP-589 [1], node status [2], kubelet config [3], controller-manager [4]) | The kubelet renews a tiny **Lease** every 10 s (lease duration 40 s) and posts the heavy NodeStatus only every 5 min or on change. Status objects "may easily exceed 15 kB"; at 5 k nodes this cut etcd writes from 150 to 30 MB/min. A failed renewal retries with backoff from 200 ms, capped at 7 s. The controller convicts after `node-monitor-grace-period` (50 s), "N times" the update interval. | Liveness must be cheap and separate from status (§5.1, §5.7, D6). The grace is a **multiple of the interval** (≈ 4–5×), not 1.5× (§5.6). Retry a failed liveness signal quickly, not with long timeouts (§5.1). |
| **kubelet reserved resources and eviction** [5][6][7] | `Allocatable = Capacity − kube-reserved − system-reserved − eviction threshold`; hard eviction at `memory.available<100Mi`. OOM scores: kubelet −999, Guaranteed −997, BestEffort 1000, Burstable `min(max(2, 1000 − 1000·request/capacity), 999)`. | Memory reserve in slot sizing (§5.2). Scanners get a higher `oom_score_adj` than the agent (§5.3). |
| **Kubernetes probes** [8] | "Incorrect implementation of liveness probes can lead to cascading failures… restarting of container under high load." | The heartbeat is liveness only. Load goes in the report and narrows dispatch, never liveness (§5.6). |
| **SWIM** [9] and **Lifeguard** [10] | SWIM adds a *suspect* state before *failed*, cutting false positives. Lifeguard shows that slow message processing on a **stressed** member makes healthy members look dead. Its local health awareness scales probe and suspicion timeouts with the detector's **own** health; false positives fell **50–100×**. | The suspicion ladder (§5.6.2). **No conviction while the platform itself is slow** (§5.6.4). Backpressure uses local signals only, never the platform's RTT (§5.4). |
| **Phi accrual** [11][12][13] | A continuous suspicion level from the observed inter-arrival distribution; Cassandra convicts at φ 8, Akka uses φ 8 with a 3 s acceptable pause "to survive… garbage collect[ion]". | Not adopted. Our interval is advised, so the expected arrival is known; phi suits unknown jitter (§5.6.5). |
| **cgroup v2** [14], **systemd delegation** [15] | `cpu.weight` 1–10000 (default 100); `memory.high` throttles and reclaims, "never invokes the OOM killer"; `memory.max` OOM-kills inside the cgroup. The no-internal-processes rule; a single writer per subtree, delegated with `Delegate=yes`. | Phase 3 per-job cgroups with `memory.high` before `memory.max` (§5.3, D7). |
| **Linux scheduling, I/O, OOM** [16][17][18][19][20] | Each nice step ≈ ×1.25 weight. SCHED_IDLE is "lower even than a +19 nice value". **Autogroup** makes nice effective only within a session. I/O priorities work on bfq and mq-deadline (the ioprio_set man page's "CFQ only" is outdated). `oom_score_adj` −1000…1000; going below the last privileged value needs CAP_SYS_RESOURCE. | nice +10 and BE level 7 on the scanner's **process group**, which stays in the sensor's session (§5.3). Raise the scanner's score; leave lowering the sensor's to the operator (D5). |
| **Go runtime** [21][22][23][24] | Go 1.25 sets GOMAXPROCS from the cgroup CPU limit and updates it. Throttling "completely pauses application execution for the remainder of the throttling period" (100 ms). GOMEMLIMIT is a soft limit; the GC is capped at 50 % CPU. Goroutines are asynchronously preemptible since 1.14. | No watchdog thread needed: scheduling lag is milliseconds (§3). GOMEMLIMIT only with Phase 3 (§5.3). |
| **Grace, lease and supervision patterns** | A grace period on top of the advised heartbeat interval; a server-provided interval that the server judges against; lease renewal in a supervisor process separate from the worker that runs the job; killing the worker, not the supervisor, when it overruns. | Grace on top of the advised interval (§5.6). The `late`/`stale` states play the part of `unknown`; re-queue only after the deadline (§5.7). The lease renewal stays in the sensor process, never in the scanner's (§5.3 OOM order). |
| **HTTP/2, gRPC keepalive** [25][26][27] | net/http's HTTP/2 health check (`SendPingTimeout`) is off by default. RFC 9113: "TCP head-of-line blocking is not addressed". gRPC client keepalive is off by default. | The control client has its own connection pool. No streams for control (§5.1, §5.8). |
| **Google SRE book** [28][29] | Process health checks and service health checks "are two conceptually distinct operations". Watchdogs crash servers "due to CPU starvation". Requests carry a criticality. | Heartbeat (liveness) on its own channel with the highest criticality. Never let load fail it (§5.1). |

**Design lessons, in short.**

1. Liveness is cheap and separate from status.
2. Judge against a multiple of the interval you advised.
3. Suspect before you convict, and don't convict while you yourself are slow.
4. Kill the worker, not the supervisor.
5. Reserve incompressible resources (memory); prioritize compressible ones (CPU, I/O).
6. A failed liveness signal is replaced, not retried with stale content.

## 5. Design

### 5.1 Control channel isolation (SDK, Phase 1)

The control plane is the heartbeat (liveness, load, doorbell). The data
plane is polls, claims, uploads and the outbox. The SRE book separates
process health checks from service health checks; KEP-589 separates the
cheap lease from the heavy status. Following both, the heartbeat gets:

- **Its own HTTP client** (`pkg/client/control_channel.go`). It is a clone
  of the API client's transport, so it keeps the same proxy, TLS settings,
  private CA and SSRF dial guard. Any proxy RFC-034 sets on the API client
  applies to it too, because the clone is taken on first use. It has its
  **own connection pool**: an upload holding the data plane's connections,
  or a stalled HTTP/2 stream if a future transport turns HTTP/2 on (RFC 9113
  keeps TCP head-of-line blocking), never holds a heartbeat back.
- **Its own timeout**: `Config.ControlTimeout`, default 15 s, never above
  `Timeout`.
- **At most one retry**: only for an idle connection the platform closed,
  which net/http does not replay for a POST. **A failed heartbeat is not
  retried with its stale report.** The next heartbeat follows after
  `core.HeartbeatRetryDelay` (10 s ± 20 % jitter, never above the interval)
  instead of the full interval. A rejected key still goes through the auth
  gate's backoff.
- **Nothing slow inside**:
  - **Version probes.** After a tool's first probe, a stale result is
    reported as it is and the tool is probed again in the background
    (`ToolRegistry.SetBackgroundRefresh`, on in sensorkit). It is
    single-flight per tool, and a `Refresh` still probes inline.
  - **The manifest exchange** is bounded by 15 s. Its failure never fails
    the heartbeat (RFC-033).

A dedicated OS thread (`runtime.LockOSThread`) or a separate watchdog
process is
not needed today. The measurements show the Go scheduler gets the heartbeat
goroutine onto a CPU within milliseconds even with 12 busy processes per
core. §5.4 reopens it if the lag metric says otherwise.

### 5.2 Headroom in slot sizing (SDK, Phase 1 for memory)

Kubernetes computes `Allocatable = Capacity − kube-reserved − system-reserved
− eviction threshold`. The sensor now does the same for memory:
`ManagerConfig.ReservedMemBytes`, default `DefaultReservedMem` = 10 % of the
memory the sensor may use, at least 256 MiB and at most 1 GiB. That memory is
kept free for result buffering and parsing, the outbox and the Go runtime.
With less than that free, the sensor still runs one slot.

**CPU is not reserved.** It is compressible: a starved scanner is slower,
not dead. A whole-core reservation would cost a 4-core sensor 25 % of its
throughput. Scanner priority (§5.3) gives the sensor the CPU when it needs
it. This is decision D4.

### 5.3 Scanner isolation (SDK, Phase 1; nested cgroups Phase 3)

Every scanner the SDK starts (`ExecuteScanner`, `StreamScanner`,
`BaseScanner`) gets `core.ApplyScannerPriority` right after `Start`:

| Knob | Value | Why | Notes |
|---|---|---|---|
| CPU nice | sensor + 10 (`setpriority(PRIO_PGRP)`) | nice 10 is the conventional "low priority" setting for a scanning agent. Each nice step is about ×1.25 CPU weight, so the sensor wins about 9:1 per thread. | **Autogroup** (on by default) makes nice relative only within a session. The scanner is in the sensor's session (`Setpgid` does not create a session), so it applies where it matters. The process group covers anything the scanner forked already. |
| I/O priority | best-effort, level 7 (`ioprio_set(IOPRIO_WHO_PGRP)`) | Scanner disk I/O yields to the sensor's outbox and state writes. | Honored by bfq and mq-deadline; `none` ignores it (this host's disks are `none`/mq-deadline). |
| `oom_score_adj` | 500 | When memory runs out, the kernel kills a scanner before the sensor (about +50 % of memory in badness). | Raising it is unprivileged; children forked after the write inherit it. Kubernetes gives BestEffort pods 1000 and the kubelet −999. |

`SENSOR_SCANNER_PRIORITY=normal` (or `Options.ScannerPriority`) turns this
off. Outside sensorkit the SDK default stays off (`core.SetScannerPriority(nil)`),
so other SDK users see no change.

**Lowering the sensor's own `oom_score_adj`** needs `CAP_SYS_RESOURCE`, which
Docker does not grant by default, and it protects the agent over other
workloads on a shared host. That is decision D5.

**Phase 3: a per-job cgroup.** On a host with cgroup delegation (systemd
`Delegate=yes`, or a container with a writable, delegated cgroup), each job
runs in a child cgroup:

- `memory.high` at the job's learned cost × 1.5: the kernel throttles and
  reclaims instead of killing;
- `memory.max` at × 2;
- `cpu.weight` 50 against the sensor's 100.

The sensor moves itself into a `sensor` leaf, because of the
no-internal-processes rule. This is the only way to give a scanner a memory
limit, which nice and oom_score_adj cannot do. It needs a setup step
operators must opt into, so it is not in Phase 1.

**GOMEMLIMIT.** Go ≥ 1.19 has a soft memory limit. We do not set it in
Phase 1: a limit below the live heap makes the GC spend up to 50 % CPU
(go.dev/doc/gc-guide). It becomes useful together with Phase 3, set to the
sensor leaf's limit. GOMAXPROCS already follows the cgroup's CPU limit on
Go ≥ 1.25.

### 5.4 Backpressure (SDK, Phase 2)

The AIMD slot window already halves on OOM kills, job timeouts and CPU
throttling. Phase 2 adds local, cause-specific signals:

- **Memory pressure**: PSI `memory.pressure` `some avg10` above 20 % in the
  sensor's cgroup (or the host's) halves the window. PSI exists since Linux
  4.20 and is per cgroup in v2.
- **Heartbeat lag** (`control.lag_ms`) above 1 s on two consecutive beats
  halves the window. This is the only local proxy for "the sensor cannot
  get a CPU".
- **Never heartbeat RTT.** A slow platform is not a reason for a sensor to
  run fewer scans (Lifeguard: local health only).

Each shed is reported on the next heartbeat (`capacity.reason`, additive).

### 5.5 Observability (SDK Phase 1, api + ui Phase 2)

Every heartbeat carries `control` (additive; the API ignores it until Phase
2):

```json
"control": {"interval_s": 30, "gap_s": 30.004, "lag_ms": 1, "build_ms": 3, "rtt_ms": 9, "failures": 0}
```

| Field | Meaning |
|---|---|
| `interval_s` | the interval it follows (the advice) |
| `gap_s` | since the previous delivered heartbeat |
| `lag_ms` | how late the timer fired: CPU starvation |
| `build_ms` | report building: probes, snapshot, manifest |
| `rtt_ms` | round trip of the previous heartbeat |
| `failures` | heartbeats lost since the previous delivered one |

Phase 2 (api):

- store the latest `control` beside the load report
  (`sensors.reported_control`, additive migration);
- compute the server-side gap as `now − last_seen_at` at each heartbeat;
- add a health reason `heartbeat_late` (gap > 1.5 × advised interval) and
  `control_slow` (lag or build > 5 s);
- write an activity entry when a sensor recovers from `late`;
- add a Prometheus histogram `sensor_heartbeat_gap_seconds` (by tenant,
  not by sensor, for cardinality).

The UI sensor detail gets a "Control channel" card with interval, gap, lag,
RTT and failures, plus a 24 h sparkline of gaps.

### 5.6 Platform tolerance (api, Phase 2: owner decisions D1–D3)

1. **The platform knows what it asked for.** Each heartbeat stores
   `heartbeat_due_at = now + advised interval`, the advice it just gave,
   since the doorbell computes it. Conviction is relative to that deadline,
   not to a global 90 s. A sensor told "come back in 120 s" is not late at
   90 s, and one told "5 s" (work pending) is noticed sooner.
2. **Suspicion ladder** (SWIM's suspect state, Lifeguard's suspicion
   timeout):

   | State | Condition |
   |---|---|
   | `online` | `now ≤ due + grace` |
   | `late` | `due + grace < now ≤ due + 2 × interval + grace`. New: shown, no notification, still dispatchable for queued work; its zone pins stay |
   | `stale` | up to `due + max(3 × interval, 90 s)`. Not dispatchable; its pending pins are released |
   | `offline` | beyond that. `sensor.offline` is notified; leases expire (5.7) |

   `grace` = max(10 s, 0.2 × interval). With the default 30 s interval:
   late at 40 s past due, stale at 100 s, offline at 120 s past due (about
   150 s after the last heartbeat). That is close to Kubernetes' 40–50 s
   grace at a 10 s renew (4–5 intervals). Busy sensors (5 s interval) go
   stale in about 25 s, which is right for a sensor that should be pulling
   work.
3. **Advice never exceeds the deadline.** The doorbell clamps its advice to
   at most ½ of the offline distance. This fixes B1 even before 1 and 2:
   the minimal fix is `MaxInterval ≤ online window / 2` (45 s with today's
   90 s).
4. **No conviction while the platform is slow** (Lifeguard's local health
   awareness). When the heartbeat handler's own p95 latency or the DB's is
   above a threshold, or the API restarted less than one offline distance
   ago, the health controller does not move anything to `offline` that
   tick. It still moves sensors to `late` and `stale`. A platform that
   cannot process heartbeats must not convict sensors for it.
5. **Phi accrual is not adopted.** Our intervals are advised, not observed,
   so the expected arrival is known exactly. Phi suits peer-to-peer
   heartbeats with unknown jitter. The `control.gap_s` history can feed it
   later if needed.

### 5.7 Leases and re-queue (RFC-030 D6 alignment, Phase 2)

- **The lease is renewed by any authenticated sensor request** that names
  the command: the heartbeat's `running` list, poll, progress, complete. A
  slim heartbeat (RFC-033 §6.12, ≈ 400 B) is cheap enough to be the lease
  renewal itself. A separate lease call (KEP-589) is unnecessary now that
  the status part is small. That is decision D6.
- **Re-queue requires both** an expired lease **and** a sensor past
  `stale`. A busy-but-alive sensor whose heartbeat was late but which still
  talks to the platform keeps its work. This avoids duplicate scans (the
  RFC-030 over-claim lesson).
- **Lease length** = max(3 × advised interval, the stale distance), clamped
  60–300 s, as in RFC-030 D6. The two thresholds are the same thing seen
  from two sides.
- **B5 fix**: a `running` command whose lease expired and whose sensor is
  offline goes back to pending (new attempt, max attempts as today). Late
  results from the old holder are refused with `409 lease-lost`
  (RFC-030 §5.4).
- **A sensor that restarts** (new `instance_id`) releases what it held
  before. Its running set is empty, so the platform re-queues at once
  instead of waiting for the lease.

### 5.8 Not done, and why

- **gRPC / long-lived streams for control.** They need keepalive tuning
  (gRPC disables client keepalive by default) and break through many egress
  proxies (RFC-034). Short HTTP requests on a dedicated pool get the
  isolation without that cost.
- **SCHED_IDLE for scanners.** On a shared host it starves scanners behind
  every other process, not only behind the sensor. nice 10 is enough.
- **Sensor watchdog process.** See §5.1: reopen only if `lag_ms` shows the
  sensor process itself starving.

## 6. Decisions for the owner

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Conviction model | (a) keep the fixed 90 s; (b) per-sensor deadline from the advised interval plus the late/stale/offline ladder (§5.6) | **(b)**. It fixes B1 and B2 at the root and uses information the platform already has. |
| D2 | B1 hotfix before D1 lands | (a) clamp doorbell advice to ≤ 45 s (½ of 90 s); (b) make the health controller use `WORKER_HEARTBEAT_TIMEOUT` (5 min) | **(a)** now. It is one line and safe: under load sensors heartbeat every 45 s instead of 120 s, about 2.7× the heartbeat rate at the moment the platform is slow. (b) delays real failover by 3.5 min. |
| D3 | When `sensor.offline` is notified | (a) at the first conviction, as today; (b) only at `offline` in the new ladder, and never while the platform is slow (§5.6.4) | **(b)**. Fewer false pages; `late` and `stale` are visible on the page without paging anyone. |
| D4 | CPU reserve for the sensor | (a) none, scanners at nice +10 (Phase 1); (b) reserve 0.25–0.5 core in the slot count | **(a)**. Measured: CPU contention does not delay heartbeats. A reserve costs a 4-core sensor up to one slot. |
| D5 | Lower the sensor's own `oom_score_adj` (e.g. −500) when it has `CAP_SYS_RESOURCE` | (a) no; (b) yes, opt-in (`SENSOR_PROTECT_FROM_OOM=true`); (c) yes by default | **(b)**. Raising scanners (Phase 1) already makes them the victims. Protecting the agent over a customer's workloads on a shared host should be the operator's choice. |
| D6 | Lease renewal channel | (a) the heartbeat's `running` list plus any command request; (b) a separate lightweight lease endpoint (KEP-589 style) | **(a)**. RFC-033's slim heartbeat already is the cheap lease. Revisit if heartbeats grow again. |
| D7 | Per-job cgroups (Phase 3) | (a) opt-in when the sensor detects a delegated cgroup; (b) not at all | **(a)**, documented for systemd (`Delegate=yes`) and Kubernetes. |

### 6.1 Owner decisions (2026-10-02)

| # | Decision | Outcome |
|---|---|---|
| D1 | Conviction model | **Yes.** Each sensor is judged against the interval the platform advised it, on a late → stale → offline ladder (§5.6.1–5.6.2). This also fixes B2: `stale` becomes reachable. |
| D2 | B1 hotfix | **Yes, urgent, its own PR.** Advised intervals are capped at half of the offline mark: ≤ 45 s with the 90 s controller (api#746). |
| D3 | When `sensor.offline` is notified | **Yes.** Only at true `offline`, and never while the platform itself is degraded or slow (§5.6.4). |
| D4 | CPU reserve for the sensor | **No.** Scanners yield the CPU through their priority (Phase 1); the measurements showed no heartbeat delay from CPU contention. |
| D5 | Sensor self-protection from the OOM killer | **Yes, opt-in, off by default** (`SENSOR_PROTECT_FROM_OOM`). A negative `oom_score_adj` needs `CAP_SYS_RESOURCE` (Docker: `--cap-add SYS_RESOURCE`; systemd: run as root or grant the capability); without it the sensor warns and runs unprotected. Scanners never inherit the negative score. |
| D6 | Leases and re-queue | **Yes.** Leases are renewed by the heartbeat's `running` list and by any other call about the command. A dead sensor's running commands are re-queued promptly, not after the 1 h run timeout (fixes B5). Duplicate execution is fenced: every claim has a lease epoch, and a completion from an older epoch is refused. |
| D7 | Per-job cgroups | **Deferred to Phase 3.** In the measurements, memory-aware slots plus scanner priority already prevented OOM, and cgroup delegation varies across Docker, Kubernetes and systemd. |

## 7. Phases

| Phase | Scope | Repos |
|---|---|---|
| **1** (no decision needed) | Control client + 1 retry + retry delay; background probes; bounded manifest sync; `control` stats on the heartbeat; memory reserve; scanner nice/ionice/oom_score_adj with `SENSOR_SCANNER_PRIORITY` | sdk-go#113; then a sensor release that takes the SDK, plus B6 (`ConfigureScannerProcess` + `ApplyScannerPriority` in the platform-mode executors and content refresh) |
| **2** | D1–D3, D6: `heartbeat_due_at`, ladder, clamp, slow-platform guard, leases with re-queue (RFC-030 Phase 1), store/show/alert `control`; SDK backpressure on PSI and lag | api, ui, sdk-go |
| **3** | D5, D7: per-job cgroups with `memory.high`, optional self-protection | sdk-go, sensor, helm-charts |

## 8. Compatibility and risks

- **Wire**: `control` is an additive heartbeat member. The API's typed
  decoder ignores it (must-ignore, RFC-029 §4.11). No API change is needed
  for Phase 1.
- **SDK API**: additions only. `client.Config.ControlTimeout`,
  `client.DefaultControlTimeout`, `core.ControlStats`,
  `SensorStatus.Control`, `core.HeartbeatRetryDelay`,
  `core.ScannerPriority` / `DefaultScannerPriority` /
  `SetScannerPriority` / `CurrentScannerPriority` / `ApplyScannerPriority`,
  `ToolRegistry.SetBackgroundRefresh`, `resource.ManagerConfig.ReservedMemBytes`,
  `resource.DefaultReservedMem` / `MinReservedMem` / `MaxReservedMem`,
  `sensorkit.EnvScannerPriority`, `Options.ScannerPriority`,
  `ResolveScannerPriority`.
- **Behaviour**:
  - A scanner that relied on running at normal priority is slower only
    while the sensor itself needs the CPU, which is rare.
  - A small sensor (≤ 2.5 GiB) loses 256 MiB of slot budget. That is one
    slot only when it was on the edge.
  - A sensor whose heartbeat fails now tries again after ~10 s instead of
    retrying three times within ~14 s: about the same load on a platform
    that is down, spread over time.
- **Proxy** (RFC-034): the control client is cloned from the API client on
  first use. A proxy RFC-034 configures on the API client's transport
  applies to heartbeats with no further change. If RFC-034 resolves a
  separate control proxy, it plugs into `controlHTTP()`, the one place the
  control transport is built.

## 9. References

1. KEP-589 Efficient Node Heartbeats — https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/589-efficient-node-heartbeats/README.md
2. Kubernetes, Node status / heartbeats — https://kubernetes.io/docs/reference/node/node-status/
3. kubelet config types (`nodeLeaseDurationSeconds`, `nodeStatusReportFrequency`) — https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/kubelet/config/v1beta1/types.go
4. kube-controller-manager flags (`--node-monitor-grace-period` 50s) — https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/
5. kubelet flags (`--oom-score-adj` −999) — https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
6. Node-pressure eviction (thresholds, OOM score table) — https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/
7. Reserve compute resources for system daemons — https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/
8. Liveness, readiness and startup probes — https://kubernetes.io/docs/concepts/configuration/liveness-readiness-startup-probes/
9. A. Das, I. Gupta, A. Motivala, "SWIM: Scalable Weakly-consistent Infection-style Process Group Membership Protocol", DSN 2002 — https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf
10. A. Dadgar, J. Phillips, J. Currey, "Lifeguard: Local Health Awareness for More Accurate Failure Detection", 2017 — https://arxiv.org/abs/1707.00788
11. N. Hayashibara et al., "The φ Accrual Failure Detector", 2004 — https://dspace.jaist.ac.jp/dspace/bitstream/10119/4784/1/IS-RR-2004-010.pdf
12. Apache Cassandra `cassandra.yaml` (`phi_convict_threshold: 8`) — https://github.com/apache/cassandra/blob/trunk/conf/cassandra.yaml
13. Akka cluster `reference.conf` (failure detector) — https://github.com/akka/akka/blob/main/akka-cluster/src/main/resources/reference.conf
14. Linux kernel, Control Group v2 — https://docs.kernel.org/admin-guide/cgroup-v2.html
15. systemd, Control Group APIs and Delegation — https://systemd.io/CGROUP_DELEGATION/
16. Linux `kernel/sched/core.c`, `sched_prio_to_weight` — https://github.com/torvalds/linux/blob/master/kernel/sched/core.c
17. sched(7) (SCHED_IDLE, autogroup) — https://man7.org/linux/man-pages/man7/sched.7.html
18. ioprio_set(2) — https://man7.org/linux/man-pages/man2/ioprio_set.2.html
19. Linux kernel, Block io priorities — https://docs.kernel.org/block/ioprio.html
20. proc_pid_oom_score_adj(5) — https://man7.org/linux/man-pages/man5/proc_pid_oom_score_adj.5.html
21. Go 1.25 release notes (container-aware GOMAXPROCS) — https://go.dev/doc/go1.25
22. Go blog, "Container-aware GOMAXPROCS" — https://go.dev/blog/container-aware-gomaxprocs
23. Go GC guide (GOMEMLIMIT) — https://go.dev/doc/gc-guide
24. Go 1.14 release notes (asynchronous preemption) — https://go.dev/doc/go1.14
25. Go `net/http` (`HTTP2Config.SendPingTimeout`, `MaxConnsPerHost`) — https://pkg.go.dev/net/http
26. RFC 9113, HTTP/2 — https://www.rfc-editor.org/rfc/rfc9113.html
27. gRPC keepalive guide — https://grpc.io/docs/guides/keepalive/
28. Google SRE book, "Addressing Cascading Failures" — https://sre.google/sre-book/addressing-cascading-failures/
29. Google SRE book, "Handling Overload" — https://sre.google/sre-book/handling-overload/
