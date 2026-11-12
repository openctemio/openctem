# RFC-074: Adaptive sensor control (measured values instead of configured numbers)

| | |
|---|---|
| Status | Proposed (2026-10-11) |
| Workflow | [sensor-platform-workflow.md](../architecture/sensor-platform-workflow.md) (the end-to-end sensor and platform flow as implemented today) |
| Scope | api (doorbell, leases, sensor route budgets, hello, control profile, Sensors API), sdk-go (`pkg/adapt` bounds and controllers, client, egress forwarder, resource manager, outbox), sensor (nuclei and tool adapters, status command), web (Sensors page) |
| Related | RFC-023 §9.2a (heartbeat doorbell), RFC-026 (ingest v2 limits), RFC-029 (control plane v2), RFC-030 (scan distribution, leases, fair share), RFC-033 (manifest, `config_version`), RFC-035 (heartbeat under load, lease epochs), RFC-038 (sensor tool settings), RFC-040 (mutual distrust, local policy), RFC-059 (transport v3 and automatic binding selection), RFC-060 (tool network confinement, egress forwarder), RFC-067 (scan windows), RFC-071 (scan intensity) |

## 1. Summary

A sensor should need nothing but its enrollment to run well. Today about 110
numbers govern how a sensor talks to the platform and how hard it works
toward targets; roughly 25 are sensor environment variables, 30 are api
environment variables and the rest are constants. A few are already measured
(job slots, the advised heartbeat interval, ingest segment sizes, certificate
and key renewal). The ones that matter most for scan quality and fleet
safety are fixed: the request rate toward targets, job deadlines, request
timeouts and retries, the push-back the platform gives, and fleet-wide pacing
after an outage.

This RFC makes every one of those values **measured, explained and bounded**:

1. **The platform advises, the sensor decides inside its local bounds.** A
   hint may always narrow; it may widen only up to the sensor's local policy
   and the compiled safe bounds (RFC-040). Security bounds (signature clock
   skew, payload caps, key lifetimes) are not adaptive.
2. **Each knob has one controller** fed by a named signal, a documented
   floor and ceiling in one bounds table, and a deterministic fallback when
   the signal is missing.
3. **Every effective value is observable with its reason**, on the sensor
   (`status`, metrics) and on the Sensors page.
4. **Environment variables become optional bounds or overrides**; the ones
   that are inert or duplicated are removed.

## 2. Problem

| Today | Effect |
|---|---|
| Rate toward targets is a constant (nuclei 150 req/s, concurrency 25, bulk 25; the egress forwarder 100 connections/s, 1000 when the tool manifest names no rate parameter, per host = global) with no feedback from the target | A WAF that answers 429/403 or drops connections makes the scan report "nothing found" (false negatives) or bans the sensor's address; a fragile customer host can be overloaded by a default |
| Job deadlines are per-scanner constants (15/30/60 min) or the scan's `timeout_seconds` (default 3600 s) | Large target sets are killed half-way; hung jobs hold a slot for an hour. The sensor already learns seconds per target per tool and does not use it |
| Request timeout 30 s, 3 retries, 2 s base, 30 s cap for every call | A heartbeat and a 16 MiB segment upload share one timeout; retries are not budgeted, so an outage multiplies load by up to 4 |
| Sensor routes answer 429 with a constant `Retry-After: 1`; the sensor is never told its budget | Sensors learn their budget only by being refused, and all retry one second later together |
| The doorbell's "loaded" interval (2 min) is always clamped to 45 s (half of the 90 s offline mark) | A configured knob that never takes effect; the platform has no working "back off" signal |
| The doorbell's maximum interval is not derived from the command lease (3 min) | Safe today only because 45 s < 3 min / 3; raising one setting can silently cause lease loss and duplicate execution |
| Fleet size does not enter the heartbeat interval | 10 000 sensors heartbeat as often as 10; the platform's load grows with the fleet without bound |
| After a platform outage every sensor reconnects and drains its outbox at once | A recovery storm can take the platform down again |
| Clock skew tolerance is ±2 min and nothing measures skew | A drifting sensor fails every signed request with no explanation |
| The operator's concurrency cap on the platform and the sensor's `SENSOR_MAX_JOBS` are separate | Nobody sees "effective = 3 because the platform cap is 3" |

## 3. Goals and non-goals

Goals
- Zero required configuration besides enrollment; existing environment
  variables keep working as bounds.
- Adaptive request rate toward each target host, never above the ceilings
  set by the scan, the scan window, the program rules, the sensor's local
  policy and the sensor operator.
- Platform push-back that tells sensors their budget and the platform's
  load, and fleet-wide pacing that scales with the number of sensors.
- One bounds table per side, generated into the docs.
- Effective values and their reasons visible to operators.

Non-goals
- Transport selection (RFC-059 automatic binding selection covers it).
- Making security bounds adaptive (clock skew window, payload caps, key and
  certificate lifetimes stay fixed or relative to their own lifetime).
- Tenant-authored tuning rules; machine-learned models. Controllers are
  simple, explainable feedback loops.

## 4. Principles

| # | Principle |
|---|---|
| P1 | **Measured default, configured bound.** A number an operator sets is a floor or ceiling for a controller, not the value itself. |
| P2 | **Platform proposes, sensor clamps.** Narrowing (slower, fewer, shorter) is always accepted. Widening is accepted up to `min(local policy, sensor bounds table)`. A clamped proposal is reported back with its reason. |
| P3 | **Safe fallback.** A controller without its signal holds the conservative default from the bounds table. Never "unlimited". |
| P4 | **Every value has a reason.** Each effective value carries `{value, source: learned \| platform \| local_policy \| operator \| default, reason, changed_at}`. |
| P5 | **One bounds table.** sdk-go `pkg/adapt/bounds.go` and api `internal/app/sensor/adaptbounds.go` hold every floor, ceiling and default with a one-line rationale; a generator writes `docs/architecture/adaptive-sensor-control.md` tables from them. A test fails if a controller reads a literal instead of the table. |
| P6 | **Security bounds are not knobs.** Signature and job-signature skew, body caps, key TTLs, scope and intensity ceilings are outside this RFC's controllers. |
| P7 | **Additive protocol.** Everything is gated on the `adaptive.v1` feature in both hellos; a sensor or platform without it behaves exactly as today. |

## 5. Design

### 5.1 Controllers (signal → controller → bounds → override)

| Knob | Signal | Controller | Bounds (bounds table) | Override |
|---|---|---|---|---|
| Heartbeat and poll interval | pending work, held leases, platform load (heartbeat handling p95, DB pool wait), fleet size | Platform: `interval = clamp(max(stateInterval, fleetSize / targetHeartbeatRate), min, maxInterval)` with `maxInterval = min(offlineMark/2, lease/3)`; ±20 % sensor jitter as today | 5 s … 45 s with today's offline mark | api env becomes min/max only |
| Command lease | the interval advised to this sensor; stream vs poll binding | Platform per claim: `lease = clamp(4 × advisedInterval + grace, 1 min, 30 min)`; renewal by heartbeat as today | 1 … 30 min | `SENSOR_COMMAND_LEASE` becomes the floor |
| Claim size | free slots, fair share | unchanged (claims = free slots, RFC-030) | ≤ 100 | — |
| Job slots | cgroup CPU/memory, learned tool cost, OOM kills, throttling, **pressure stall information (PSI)** | unchanged AIMD window plus PSI: `cpu.some avg10 > 40 %` or `memory.some avg10 > 10 %` counts as congestion before an OOM kill | 1 … local cap (≤ 64) | effective = `min(SENSOR_MAX_JOBS, platform operator cap, slots)`; the platform cap is sent as a narrowing hint |
| Request timeout | per call class (control, claim, upload, download) round-trip time | RFC 6298 estimator: `RTO = SRTT + 4·RTTVAR`, scaled by body size for uploads, doubled on timeout | 2 s … 60 s (uploads by size up to 10 min) | — |
| Retries | failures per call class | token-bucket retry budget (retries ≤ 10 % of requests, minimum 1 per 10 s), per-request cap 3, full jitter; per-class circuit breaker (open after 5 consecutive transient failures, half-open probe after `max(Retry-After, RTO × 4)`) | caps in table | — |
| Client pacing | `RateLimit` / `RateLimit-Policy` fields, `Retry-After`, `X-OpenCTEM-Load` | local token bucket per route class sized at 80 % of the advertised policy; load ≥ 0.8 doubles non-urgent intervals (config report, manifest, logs flush) | server policy | — |
| Segment in-flight and size | upload throughput, 413, timeouts | AIMD on in-flight segments (1 … hello max); segment size halves on timeout, grows back to the hello maximum after clean uploads | hello `limits` | — |
| Compression | upload throughput vs CPU headroom | zstd level 1 when CPU-bound, 3 by default, 9 on slow links (< 1 MiB/s) with idle CPU | hello encodings | — |
| Outbox drain | `drain_rate` hint, success | AIMD from 1 item in flight up to the hint; per-item backoff as today | local outbox caps | — |
| **Rate toward targets** | per destination host, from the egress forwarder: connect failures, resets, timeouts, TLS failures, connect latency; from HTTP-aware tools and guarded ports: 429, 503, challenge-page 403, `Retry-After` | per-host AIMD in the forwarder: halve on a congestion window, +10 % of the ceiling per clean window, `Retry-After` honoured per host; host breaker after N consecutive failures marks the host "unreachable" for the job (reported as coverage gap, not "no findings"); tool flags (`-rate-limit`) start at the controller's current value for the job's hosts | **never above `min(scan rate_limit, scan window rate_limit_rps, program rule cap, local policy rate.max_rps, SENSOR_<TOOL>_MAX_*)`**; floor 1 req/s | per scan: "fixed rate" (the controller only narrows on hard errors) |
| Job deadline | cost book seconds per target (p90), target count | `deadline = clamp(3 × estimate + 5 min, 5 min, min(scan timeout_seconds, local max_job_seconds, 24 h))`; a job that passes the estimate reports progress in logs; the deadline never exceeds the ceiling | table | scan `timeout_seconds` stays the ceiling |
| Clock | `Date` header / `server_time`, min-RTT sample | offset estimate (NTP-style midpoint of the lowest-RTT sample in the last 10 calls) | warn ≥ 30 s, alert ≥ 90 s | none: verification windows never widen; the offset is reported, not applied to inbound verification |
| Content refresh | content version in the control profile | refresh when the platform's content version changes; safety refresh every 24 h | 10 min … 720 h | `SENSOR_CONTENT_REFRESH_INTERVAL` becomes the ceiling |
| Log verbosity | platform action `debug` with an expiry | debug logging until expiry, then back | ≤ 1 h; no secret values are ever logged | local `verbose` |
| DNS resolvers | per-resolver latency and failures | rank and fail over within the operator's list (or the system list) | operator list only | `SENSOR_DNS_RESOLVERS` |

### 5.2 Platform side

**Doorbell.** The interval becomes a function, not three constants:
`stateInterval` (busy when work waits or a held command was canceled, idle
otherwise), stretched by fleet size (`fleetSize / targetHeartbeatRate`,
default target 50 heartbeats/s per api replica, computed server-side from the
active-sensor count, never from sensor input) and by platform load (the
existing heartbeat-handling p95 from the health guard, plus DB pool wait),
clamped to `[min, min(offlineMark/2, lease/3)]`. The deadline-based liveness
ladder already follows the advised interval, so stretching never convicts a
healthy sensor.

**Leases.** The lease on a claim is derived from the interval advised to that
sensor (`4 × interval + grace`) so the two can no longer drift apart.

**Push-back.** Every sensor route answers with:
- `RateLimit-Policy` and `RateLimit` (draft-ietf-httpapi-ratelimit-headers)
  for the per-sensor and per-tenant budgets that apply to the route class;
- a `Retry-After` computed from the limiter's refill time, plus up to 50 %
  jitter, instead of a constant 1;
- `X-OpenCTEM-Load: <0.0-1.0>`, a coarse platform load bucket (four steps)
  from api saturation (in-flight requests, decode budget, DB pool wait);
- after an outage or restart, a `drain_rate` hint in the heartbeat answer that
  ramps from low to normal over a recovery window, so outboxes drain without
  a storm.

On transport v3 the same values travel in a `ControlHints` message on every
response and on the control stream.

### 5.3 Sensor side

A new sdk-go package `pkg/adapt` holds the bounds table, the controller
types (AIMD, RTO estimator, retry budget, breaker, offset estimator) and an
`Effective` registry: every controller publishes its current value and
reason there. The client, the command poller, the outbox, the resource
manager and the egress forwarder read from it. `openctem-sensor status`
prints the registry; the heartbeat carries a bounded summary (§5.5).

The egress forwarder (RFC-060) already sees every connection of a confined
tool, so the per-host rate controller lives there; tools that do not run
confined get the same controller through their adapter (nuclei's
`-rate-limit` and `-max-host-error` are set from it, and its JSON output is
read for per-host error counts).

### 5.4 Control profile with acknowledgement

`config_version` today says only that "something changed". It becomes the
version of a **control profile**:

```
ControlProfile {
  version:        uint64, monotonic per sensor
  issued_at:      timestamp
  bounds_version: string    // which bounds table the platform used
  values: {                 // proposals; each optional
    max_jobs, heartbeat_min, heartbeat_max, target_rate_ceiling,
    job_deadline_ceiling, content_version, debug_until, drain_rate
  }
}
```

- Fetched on version change (v2 `GET /api/v2/sensor/control-profile`, v3
  `GetControlProfile`), signed with the job-signing key when the platform signs
  jobs (RFC-040), otherwise carried on the authenticated channel.
- The sensor validates each value against its bounds and local policy, applies
  what fits, and reports on the next heartbeat:
  `{applied_version, rejected_version?, clamped: [{key, proposed, applied, reason}]}`.
- A version not above the applied one is ignored (rollback protection). A
  rejected profile leaves the last applied one in force.
- RFC-038 tool settings keep their own signed document; the control profile
  carries only communication and pacing values.

### 5.5 Telemetry the sensor reports

Bounded, numeric, per heartbeat (or every Nth heartbeat when large):
effective values with source and reason codes; RTT p50/p95 and error counts
per call class; retry-budget and breaker state; clock offset; outbox depth;
per-job target-rate summary (start, minimum, final rate, hosts throttled,
hosts unreachable) attached to the command completion, not the heartbeat,
because host names are tenant data that belong to the job's result. The
platform clamps every field, stores the latest per sensor, and exports
fleet-wide aggregates (histograms, no host names) to its metrics.

### 5.6 Interface

Sensor detail gains **Communication and limits**: each effective value, its
source (learned / platform / local policy / operator / default), the reason,
when it last changed, and any proposal the sensor clamped (a badge on the
fleet list when a sensor refuses or clamps the platform's profile). Scan run
details show the per-job rate summary and hosts that throttled or became
unreachable as coverage gaps. Overrides exist only where a human decision is
meaningful: the platform concurrency cap per sensor, "fixed rate" per scan,
heartbeat bounds (platform administrator), and a time-boxed debug window. All
text goes through i18n keys.

## 6. Security and threat model

| Threat | Control |
|---|---|
| Hostile or compromised platform sends hints that widen safety (higher rate, more slots, longer deadlines, other resolvers, a proxy) | The sensor clamps every value to `min(local policy, bounds table)` (P2). Resolvers, proxy, scope and intensity are not in the profile at all. A clamped or rejected proposal is logged locally and reported. |
| Platform replays an old, wider profile | Monotonic version per sensor; signature by the job-signing key when available. |
| Platform shifts the sensor's view of time to replay signed jobs | The clock offset is reported only; it is never applied to the verification of inbound signatures. |
| Hostile sensor reports fake telemetry to get more budget or slow others | Telemetry only shapes advice for that sensor; fleet size and platform load are computed server-side; per-sensor and per-tenant budgets stay enforced by the api regardless of advice; every field is range-clamped. |
| Hostile sensor stretches its lease | The lease is computed by the api from its own advice and bounded to 30 min. |
| Cross-tenant inference from load hints | `X-OpenCTEM-Load` is a four-step bucket of api saturation; no counts of other tenants' sensors or jobs. Fleet-size scaling uses the platform's total, exposed only through the interval. |
| Recovery storm after an outage | Jittered `Retry-After`, `drain_rate` ramp, fleet-scaled intervals, retry budgets. |
| Adaptive rate causes harm to a target | The controller can only go below the ceilings; on hard errors it backs off; the host breaker stops probing an unreachable host. |
| Controller bug runs away | Every controller has a floor and ceiling from the bounds table and a test per bound; P3 fallback is conservative. |

Authorization and isolation: profile reads and telemetry writes use the
sensor's existing identity (key-bound signature or mTLS); every query is
scoped to the sensor's tenant (platform sensors to the platform scope).
Sensors page reads need `sensors:read`; the overrides need the existing
sensor write permission; heartbeat bounds are platform-administrator only.
Tests: cross-tenant reads of another tenant's sensor profile and telemetry
are refused; a profile above local bounds is clamped; a rollback version is
ignored.

## 7. Migration

| Setting | Becomes |
|---|---|
| `SENSOR_MAX_JOBS`, `SENSOR_NUCLEI_MAX_RATE_LIMIT`, `_CONCURRENCY`, `_BULK_SIZE`, local policy `rate.*` | Local ceilings (unchanged meaning) |
| `SENSOR_OUTBOX_MAX_BYTES`, `_MAX_AGE` | Local ceilings (unchanged) |
| `SENSOR_CONTENT_REFRESH_INTERVAL` | Ceiling of the safety refresh |
| `SENSOR_DNS_RESOLVERS` | The list the resolver ranking chooses from |
| `heartbeat_interval`, `poll_interval` (sensor file) | Used only when the platform has no doorbell; deprecated |
| api `SENSOR_HEARTBEAT_INTERVAL`, `_BUSY_INTERVAL` | Deprecated (computed) |
| api `SENSOR_HEARTBEAT_LOADED_INTERVAL` | Removed (inert today) |
| api `SENSOR_HEARTBEAT_MIN_INTERVAL`, `_MAX_INTERVAL` | Bounds (unchanged) |
| api `SENSOR_COMMAND_LEASE` | Lease floor |

A sensor without `adaptive.v1` keeps today's behaviour; a platform without it
answers today's hints, and the sensor's controllers run on local signals only
(slots, RTO, retry budget, target rate, deadlines all work without the
platform).

## 8. Delivery plan

Small PRs, biggest value first. Each phase is independently useful.

| Phase | Repo | Change | Value |
|---|---|---|---|
| P0 | api | Derive the doorbell maximum from `min(offlineMark/2, lease/3)`, remove the inert loaded interval, compute `Retry-After` from the limiter refill time with jitter | Removes a latent duplicate-execution trap and the synchronized retry |
| P1a | sdk-go | `pkg/adapt` bounds table, AIMD and breaker types, `Effective` registry | Foundation, no behaviour change |
| P1b | sdk-go | Per-host rate controller in the egress forwarder with host breaker and coverage-gap reporting | Fewer WAF bans and false negatives; no customer overload |
| P1c | sensor | nuclei adapter starts from the controller's rate, reads per-host errors, reports the rate summary | Same, for the busiest tool |
| P2 | sdk-go | Learned job deadlines from the cost book | Fewer half-finished large scans; hung jobs freed sooner |
| P3 | api | Fleet-size and load terms in the doorbell, lease derived per claim, `X-OpenCTEM-Load`, `drain_rate` after restart | Platform load bounded as the fleet grows; no recovery storm |
| P4 | sdk-go | Per-class RTO, retry budget, control-client breaker, `RateLimit` field pacing | Outages no longer multiply load; uploads stop sharing a heartbeat timeout |
| P5a | api | `RateLimit-Policy` / `RateLimit` on sensor routes; `server_time` and `adaptive.v1` in hello | Sensors pace instead of being refused |
| P5b | api + sdk-go | Control profile with acknowledgement and clamp reporting; clock-offset telemetry | Drift and refusals visible; one place for platform proposals |
| P6 | web | Communication and limits panel, clamp badges, run rate summary | Operators see what runs and why |
| P7 | sdk-go | Adaptive segment in-flight/size, compression level, PSI in the slot controller | Throughput on slow links; earlier back-off before OOM |

## 9. Open questions

1. Default "fixed rate" or "adaptive rate" for scans that set an explicit
   `rate_limit`? Proposal: adaptive below the explicit value (the value is a
   ceiling).
2. Should a host that trips the breaker fail the job, or complete it with a
   coverage gap? Proposal: complete with a coverage gap, surfaced on the run.
3. Target heartbeat rate per api replica (proposal 50/s) and whether it scales
   with the replica count automatically.
4. Is a debug window that the platform can open on a customer's sensor
   acceptable by default, or only with the sensor's local policy opting in?
   Proposal: local policy opt-in, mirroring support access.
