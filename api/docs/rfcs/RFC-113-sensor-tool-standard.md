# RFC-113: Sensor tool standard (one contract for jobs, targets and results)

| | |
|---|---|
| Status | Proposed (2026-10-17). Design only; nothing in this RFC is built yet except where a section says "exists" |
| Scope | ctis (`job`, `outcome` execution block, CTIS 1.7), sdk-go (native tool executor, `Task`, `Context`, adapter protocol additions, `sensortest`, removal of legacy interfaces), sensor (built-in tools on one registration), connector products (on the tool contract), api (one job builder, execution ingest, stop reasons, checkpoints, artifact upload, credential references) |
| Architecture | [tool-contract.md](../architecture/tool-contract.md), [sensors.md](../architecture/sensors.md), [scan-orchestration.md](../architecture/scan-orchestration.md) |
| Related | RFC-033 (sensor manifest), RFC-040 (mutual distrust, signed jobs, credentials by reference), RFC-055 (tool contract v1), RFC-074 (adaptive control), RFC-084 (file storage), RFC-090 (work pool), RFC-092 (tool-agnostic platform), RFC-094 (contracts only), RFC-100 (shared sensors); sdk-go `docs/rfcs/sensor-sdk-v2.md` and `docs/adapter-protocol.md` |

## 1. Summary

A third party that wants its tool to run on OpenCTEM sensors should write one
descriptor and one function, run one test command, and have everything else
work: receiving jobs and targets, budgets, scope, credentials, results,
progress, retries, cancellation, restarts and coverage.

Most of that contract exists (RFC-055, the SDK's `pkg/tool`, adapter protocol
v1, the exec profile, the `openctem tool` CLI). What is missing is that it is
the **only** contract. Today:

- the sensor runtime still runs every tool through an older scanner
  interface, which drops artifacts, the task id, the attempt and the target
  types on the way;
- built-in tools implement two interfaces and register in six places;
- the connector product uses a third, hand-written command path;
- the job is an untyped map built by two builders with different keys;
- per-target outcomes travel in five different places;
- several mechanisms the use cases need do not exist at all: a checkpoint or
  cursor, delivery during a task, artifact upload, relationship records, a
  stop reason, credential references in jobs, and a probed engine version.

This RFC declares **Tool Standard v1**: four contracts, one interface, one
runtime path.

| Contract | Form | State |
|---|---|---|
| Descriptor | `tool.yaml`, `openctem.io/tool/v1` | exists (RFC-055 §4); additive keys only |
| Job document | `openctem.job/v1` payload, typed in `ctis/job`, hashed into the signed statement | statement exists (RFC-040 §5.6); the payload is typed here |
| Event stream | adapter protocol v1 | exists; three negotiated additions |
| Result envelope | CTIS with an `execution` block (CTIS 1.7) | new, replaces ad-hoc report properties |

The Go interface stays what it is today:

```go
type Tool interface {
	Manifest() Manifest
	Run(ctx Context, task Task) error
}
```

## 2. Problem (measured on develop, sdk-go main, sensor main, 2026-10-17)

| # | Finding | Effect |
|---|---|---|
| P1 | The runtime wraps each tool as a legacy scanner (`toolcompat.AsScanner`) and flattens its outcome to raw report bytes that are parsed again | artifacts are never uploaded (the file importer's VEX statements are silently lost); `Task.ID` is synthesised and `Task.Attempt` is never set; targets arrive untyped |
| P2 | Built-in tools implement the scanner interface **and** `tool.Tool`, and register in six tables | a new built-in touches six places; tool facts can disagree |
| P3 | The connector product handles its commands with its own executor | no descriptor, no sandbox, no per-target outcomes, incremental sync by a fixed window instead of a cursor |
| P4 | The job payload is an untyped map built by two builders with different keys (`run_id`/`scan_run_id`, `scanner_config`/`config`) | the SDK guesses keys; drift is silent |
| P5 | Per-target outcomes are carried as `target_outcomes`, `failed_targets`, `unfinished_targets`, `refused_targets`, `throttled_targets` and `metadata.unreached`; coverage settles from the command result only | three readers, five writers, one meaning |
| P6 | Five error vocabularies (tool classes, outcome classes, command fail codes, refusals, a deprecated error package) | the platform cannot map a failure to one action |
| P7 | No checkpoint or cursor | a paused, restarted or long task starts again from the first target; importers cannot resume |
| P8 | One report per task | nothing reaches the platform until the tool ends; downstream steps wait |
| P9 | No artifact upload route | evidence files never arrive |
| P10 | 13 author-facing interfaces and a dozen deprecated packages; docs and examples teach the legacy path | a newcomer cannot tell which contract is real |

## 3. Principles

1. **The platform decides, the sensor executes, the tool reports.**
   Placement, sizing, budgets, retries, rerouting, stall, resume and coverage
   are platform decisions. The SDK runtime enforces and measures. A tool only
   reads its task and reports what happened per target.
2. **Every mechanism lives once, in the SDK runtime.** A tool author never
   writes claim, lease, heartbeat, signature checks, scope or egress logic,
   chunk iteration, rate limiting, retries, batching, outcome bookkeeping,
   provenance, graceful shutdown, logs or metrics.
3. **Mutual distrust.** Jobs are signed and verified (RFC-040). The sensor's
   local policy only narrows. Tool output is hostile input and is checked on
   both sides. Provenance is stamped by the runtime, never by the tool.
4. **Smallest contract that covers today's use cases.** New concepts appear
   only where an existing one cannot carry the case (§10 lists what is left
   out and why).

## 4. The standard

### 4.1 Ownership

```
tool author ── tool.yaml + Run(ctx, task)                    the only code a third party writes
   │  adapter protocol v1 (NDJSON on stdio); in-process only in tests
SDK runtime ── admission, sandbox, egress, budgets → native flags, outcome ledger,
   │           checkpoint, batching, provenance, outbox, stop and shutdown, logs
   │  sensor protocol (claim, heartbeat, results); never visible to a tool
platform ───── plans by capability, sizes and signs tasks, decides retry, stall,
               reroute and resume, stores checkpoints, ingests, settles, feeds coverage
contracts ──── ctis: capability, job, outcome + execution, tooloption, politeness,
               addrscope, settings, importer
```

### 4.2 The author interface and the seven rules

`Tool` (§1) is the only interface. `tool.Define(...)` builds one from a few
declarations and a handler; `tool.New[C]` builds one from a full manifest and a
typed config. `tool.Retester` stays the one optional interface (retest tasks).

`Context` (exists) gains two methods:

| Method | Purpose |
|---|---|
| `Log()`, `Progress(done, total, msg)` | redacted, capped logs; coarse progress for one long target |
| `Emit()`: `Asset`, `Finding`, `Dependency`, `Endpoint`, `Report`, **`Relation`** (new) | records, checked when they are emitted |
| `TargetDone`, `TargetError(t, err)`, `TargetSkipped` | per-target settlement: progress, outcome, coverage |
| **`Checkpoint(v any) error`** (new) | opaque state, latest wins, at most 64 KiB of JSON, handed to the next attempt or the next import run |
| `Artifact(name, mediaType)` | a size-capped file the runtime uploads |
| `Workdir()`, `Secret(name)`, `HTTP()`, `tool.Dial` | private directory, declared credentials, confined network |

`Task` (exists) gains `Kind` (`scan`, `retest`, `check`, `import`), `Budget`
(`PerTarget`, `Task`, `Stall`) and `State` (the checkpoint or cursor), and
loses `Local` (an escape hatch that carries a serialised legacy scanner).

A tool follows seven rules, and the conformance kit checks each one:

1. The descriptor is the truth: outputs within `produces`, inputs within
   `consumes`, network within `permissions`.
2. Every finding and dependency names the target it is about.
3. Each target is settled as soon as its result is known (or the
   `toolexec.StreamJSONL` helper settles it from a record-to-target mapper).
4. The tool returns promptly when its context ends.
5. The tool reaches the network only through the sandbox (`ctx.HTTP()`,
   `tool.Dial`, or the forwarder the runtime configures).
6. The tool keeps no state outside its working directory and its checkpoint:
   no global caches, no files elsewhere. This is what makes shared sensors,
   restarts and offline runs safe.
7. Failures are classified with the helpers (`Unreachable`, `Invalid`,
   `Refused`, `RateLimit`, `Retry`, `Failed`); a plain error is `tool_error`.

Optional helpers add no concepts: `toolexec` (safe CLI execution with an
environment allow-list, extra-argument checks, process groups and output
caps), `toolexec.StreamJSONL`, `RunPerTarget`, `RunWaves`, and the
`ctis/importer` parsers.

### 4.3 The job document `openctem.job/v1`

The signed statement stays as RFC-040 §5.6 and the signer define it (tenant,
sensor, command, type, tool, payload digest, targets, templates, limits, lease
epoch, issue and expiry times, sequence, nonce, signer). The **payload** whose
digest it carries becomes one typed structure in `ctis/job`, built by one
platform builder and decoded strictly by the SDK into `tool.Task`:

```yaml
kind: scan                     # scan | retest | check | import
capability: probe.http@1
tool: {name: example-probe, descriptor_digest: "sha256:…"}   # schema the settings were validated against
params: {…}                    # capability standard params
settings: {…}                  # merged tool configuration layers
targets:                       # typed units; ref = the platform's item id, stable across attempts
  - {ref: "it_123", type: url, value: "https://a.example.com", attrs: {port: "443"}, host_keys: ["a.example.com"]}
scope: {exclusions: […], web: {…}, limits: […]}
budget: {target_s: 30, task_s: 900, stall_s: 300}            # the deadline is the statement's expiry
limits: {per_host_rps: 10, per_host_concurrency: 2, total_rps: 200}
credentials: [{name: web_login, provider: file, ref: "web-login"}]   # references, never values
state: {kind: resume, data: {…}, digest: "sha256:…"}          # resume | cursor; at most 64 KiB
content: [{slot: templates, kind: example-templates, digests: […]}]
inputs: […]                    # parser files, by upload reference
retest: […]                    # kind retest only
http: {identity: {…}}          # program identification headers
run: {run_id: "…", step_id: "…", attempt: 1}                 # correlation; attempt reaches the tool
```

Rules:
- The SDK decodes strictly. An unknown key refuses the job as
  `invalid_input`, so drift between the platform and the SDK fails loudly. A
  new key therefore ships in the SDK first and in the platform second.
- Every target `ref` comes back in the outcomes.
- The digests of `credentials` and `state` are inside the signed statement.
- The tenant never appears in the payload; it comes from the statement and
  the transport identity.

### 4.4 Event stream: three additions to adapter protocol v1

| Message | Direction | Negotiation | Meaning |
|---|---|---|---|
| `checkpoint {data}` | tool → runtime | feature `checkpoint` | latest wins; at most 64 KiB; sanitised like a record |
| `stop {reason}` | runtime → tool | feature `stop_reason`; a tool without it gets `cancel` | `cancel` discards; `pause`, `yield`, `stall`, `shutdown` and `deadline` deliver what is settled |
| `record {kind: relationship}` | tool → runtime | none (a new record kind) | a CTIS relationship; both ends resolve inside the task's report or to a task target |

All other messages are unchanged. Records are already sent one by one; the
runtime, not the tool, groups accepted records into delivery batches.

### 4.5 Result envelope: CTIS 1.7 `execution` block

```yaml
version: "1.7"
assets: […]; findings: […]; dependencies: […]; relationships: […]; endpoints: […]
execution:
  command_id: "…"
  lease_epoch: 3
  batch: {seq: 4, final: true}
  status: partial              # final batch only: ok | partial | failed | canceled
  class: tool_crashed          # §4.6, when status is not ok
  detail: "…"                  # at most 256 bytes, redacted
  targets:
    - {ref: it_123, state: done}
    - {ref: it_124, state: failed, class: unreachable}
    - {ref: it_125, state: unfinished}
  checkpoint: {data: {…}, digest: "sha256:…"}
  artifacts: [{name: shot.png, media_type: image/png, sha256: "…", size: 81234}]
  provenance: {tool: …, adapter_version: …, descriptor_digest: …, engine_version: …, binary_sha256: …,
               content: [{slot: …, digest: …}], capability: probe.http@1, sandbox: enforced}
  effective: {settings_digest: …, rate: …, concurrency: …, per_target_timeout_s: …}
  stats: {records: …, bytes: …, quarantined: …, duration_ms: …, cpu_ms: …}
```

- `execution.targets` replaces every ad-hoc per-target property (§2 P5).
- The command's `complete` call carries the same block, so ingest, coverage
  settlement and the run page read one structure.
- The platform keeps stamping tenant, sensor and command from the transport.
  It accepts an `execution` block only for the command the sensor holds at
  that lease epoch, intersects `targets[].ref` with the job's targets, and
  prefers its own measurements over reported provenance where it has them.
- Batches are idempotent by `(command_id, lease_epoch, batch.seq)`, on top of
  today's replay check by report segment digest.

### 4.6 Error classes and platform actions

One enum in `ctis/outcome`, used at task level and per target.

| Class | Set by | Meaning | Platform action |
|---|---|---|---|
| `invalid_input` | tool, runtime | the configuration or targets are wrong for this tool | fail without retry; show the admin the JSON pointer |
| `refused` | runtime (scope, local policy, tier) | this sensor will not run it | put the sensor on the item's avoid list and reroute; never retry on this sensor |
| `excluded` | runtime | an exclusion matched | skipped, no retry |
| `unreachable` | tool, runtime | no route, name not resolved, blocked, connection refused | reroute to another vantage, then fail the item as unreachable; coverage `failed` |
| `timeout` | tool, runtime | the per-target budget is spent | retry once with a larger learned budget, then fail |
| `rate_limited` | tool | the target or vendor throttled | retry after the stated delay; lower the learned rate |
| `auth_failed` | tool | credentials rejected | fail without retry; notify the owner of the credential or connection |
| `not_found` | tool | the resource is gone | fail without retry |
| `transient` | tool | a flaky dependency | retry with back-off |
| `tool_error` | tool | the tool failed | retry once on another sensor; an item that fails on two sensors is isolated |
| `tool_crashed`, `resource_exhausted` | runtime only | the process died or hit a limit | as `tool_error`, delivering what was settled |
| `output_rejected` | runtime only | protocol violation or output outside the descriptor | fail, never partial |
| `egress_refused` | runtime only | the sandbox refused a destination | as `refused` |
| `deadline` | runtime only | the task's hard limit | partial; unfinished items are planned again |
| `canceled` | runtime only | the platform canceled | discard |

A tool cannot report a runtime-only class. The current command fail codes map
onto this enum one to one.

### 4.7 Lifecycle: one mechanism for pause, restart, imports and long runs

```
platform  plan items → claim (lane, size by budget) → sign statement → deliver
SDK       verify → admit (policy ∩ job) → resolve credential references → sandbox → run
            heartbeat: held ids, progress {done, total}, activity {records, bytes, cpu}
            heartbeat answer: cancel ids, stop {id, reason}
            batches: CTIS + execution {batch.seq} → outbox → ingest (idempotent)
          final: execution {status, targets, checkpoint, provenance} → complete
platform  settle items → retry, reroute, resume, coverage
```

- **Pause** (a user, or a scan window closing): stop with reason `pause`;
  the runtime delivers settled targets and the latest checkpoint and releases
  the lease without counting an attempt; the unfinished items are held.
  **Resume** plans those items again with the stored checkpoint.
- **Sensor restart**: the same with reason `shutdown`, triggered by SIGTERM.
  The platform requeues the unfinished items at once instead of waiting for
  the lease to expire.
- **Long-running tools**: no task runs longer than the platform's maximum
  task budget (24 hours). Longer work is a chain of tasks joined by
  checkpoints. Liveness is measured by settled targets, records, output bytes
  and CPU time (RFC-090, research on run liveness); the run cap is a policy,
  not a clock.
- **Importers** (class `connector`): scheduled `import` tasks whose `state`
  is the last committed cursor. A cursor commits only together with the
  batch that carries the records up to it. Records are delivered at least
  once and ingest is idempotent.
- **Connection test**: a `check` task verifies credentials and reachability
  and emits nothing.
- **Cancel**: reason `cancel`; nothing more is delivered (fenced by the lease
  epoch).

### 4.8 Versioning and compatibility

| Contract | Version | Rule |
|---|---|---|
| Descriptor | `openctem.io/tool/v1` | additive keys only; `sdk.min` gates new keys; a breaking change is `v2` with `openctem tool migrate` |
| Job payload | `openctem.job/v1` | additive; strict decode in the SDK, so a key ships SDK first, platform second |
| Adapter protocol | 1 | new messages only behind `hello` features; unknown messages ignored outside the handshake |
| Result | CTIS 1.7 | receiver first: the platform reads `execution` and the old properties for one release train, then refuses the old properties |
| SDK | semver with stability tiers | `pkg/tool`, `pkg/sensortest` and the `pkg/sensorkit` façade are frozen at v1.0.0; everything else is internal |
| Capability | `id@major` | unchanged (RFC-055 §10) |
| Deprecation | one release train | no long-lived shims |

## 5. Use cases

| Use case | Tool author | SDK runtime | Platform |
|---|---|---|---|
| One-shot CLI tool | `tool.yaml` with `run.profile: exec` | sandbox, parse with `ctis/importer`, settle | plan, ingest |
| Long-running tool | settle per target; optional checkpoint | heartbeat, liveness counters, hard cap, stop with delivery | budget from history; chain tasks by checkpoint |
| Streaming tool | emit records as found | batch flush; idempotent batches | ingest per batch; the next step starts on the first batch |
| Target lists that need chunking | read `task.Targets` | one process for the list (`input.batch`) | items and lanes, sized at claim (RFC-090) |
| Wildcard scope | nothing | — | a wildcard is a scope rule, never a target; discovery takes the apex |
| CIDR targets | read a range target; may expand it natively | confine egress to the piece | cut ranges into pieces of at most /24 (/120) |
| Discovery of new assets and relations | emit assets and relations; never scan them in the same task | enforce `safety.expands_targets` | scope-check outputs, stream them to the next step |
| Per-host rate budgets | map common options (`timeout`, `rate`, `concurrency`, `retries`) | derive native flags from the budget; token bucket per politeness key in the forwarder | per-host limits in the job, learned and capped by policy |
| Credentialed scans | declare credentials; `ctx.Secret(name)` | resolve references on the sensor; hand values only in the run message; mask; wipe | send references only; the signer checks reference ranges; never to shared sensors |
| Passive importers | class `connector`, `import` tasks with a cursor | vendor-host egress only | schedule; store the cursor per connection, tool and stream |
| Findings with evidence | evidence items; mark sensitive headers | redact, cap | mask; reveal with permission |
| Large artifacts | `ctx.Artifact` | cap, hash, upload with a command-bound grant | store in file storage (RFC-084); link from evidence by digest |
| Incremental or partial results | settle as targets finish | partial on stop, unfinished listed | settle per item; requeue only unfinished |
| Cancellation | return on context end | stop `cancel`, grace, kill, discard | items canceled |
| Pause and resume | nothing (optional checkpoint) | stop `pause`, deliver, release | hold and re-plan |
| Retries and idempotency | never retry a whole task | batch keys; stable report id | attempts, avoid lists, isolation |
| Sensor restart mid-job | nothing | stop `shutdown`, deliver, release | requeue unfinished at once |
| Unreachable targets | `tool.Unreachable(err)` | reach class | reroute, then fail |
| Deadlines and liveness | set native per-request timeouts from the budget, or let common options do it | liveness counters; hard stop | stall on no growth; overrun cap |
| Version and content provenance | declare the version probe and content slots | probe, hash binary and content, stamp | show; tie coverage to content |
| Capability advertisement | `implements` | descriptor in the manifest by digest | facts index, placement |
| Offline sensors | nothing | file transport for job and result (later) | long-expiry signed job, bundle upload bound to the command (later) |
| Shared sensors serving many tenants | rule 6 (no state across tasks) | fresh sandbox and directory per task, signed jobs only | instance key set, per-job binding (RFC-100) |
| Logs | `ctx.Log()` or stderr | redact, cap, per-command log | show on the run page |
| Error taxonomy | error helpers | runtime-only classes | action table (§4.6) |
| Coverage ledger | report `done` only when the capability really ran on the target | — | ledger from `execution.targets` and the content provenance |
| Conformance for third parties | `openctem tool test` | scenario suite (§6.2) | certification attests the result |

## 6. Developer experience

### 6.1 A complete tool in Go (about 30 lines)

```go
package main

import (
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

var Tool = tool.Define("dotenv-check", "1.0.0").
	Implements("dast.web@1").
	Targets("url").
	Produces("finding:misconfiguration").
	Params(tool.StringParam("path").Default("/.env").Pattern("^/").MaxLength(256)).
	Handle(func(ctx tool.Context, job *tool.Job, emit tool.Emit) error {
		for _, t := range job.Targets() {
			resp, err := ctx.HTTP().Get(t.URL(job.Param("path").String()))
			if err != nil {
				ctx.TargetError(t, tool.Unreachable(err))
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == 200 {
				emit.Misconfiguration(t, tool.Issue{RuleID: "dotenv-exposed",
					Title: ".env file is publicly readable", Severity: "high"})
			}
			ctx.TargetDone(t)
		}
		return nil
	}).
	MustBuild()

func main() { adapter.Serve(Tool) }
```

The binary prints its manifest with `--describe`; `openctem tool init --kind
go` writes the matching `tool.yaml`; `openctem tool test .` runs the
conformance kit; the directory goes into the sensor's adapter directory. A tool
with no code is a `tool.yaml` with `run.profile: exec` around a CLI that writes
SARIF, CTIS or JSON with a mapping.

### 6.2 `pkg/sensortest`

One test package replaces `pkg/testkit` and `pkg/conformance` (both kept as
aliases for one minor release).

```go
func TestTool(t *testing.T)   { sensortest.Run(t, Tool, sensortest.Suite{Capability: "dast.web@1"}) }
func TestSensor(t *testing.T) { p := sensortest.NewPlatform(t); _ = p /* point your sensor at p.URL */ }
```

`sensortest.Run` (Go, in process) and `openctem tool test` (any language) run
the same scenarios:

| # | Scenario | Passes when |
|---|---|---|
| C1 | descriptor lint, handshake, describe equals the file, strict validation | as today |
| C2 | fixtures against golden CTIS | as today |
| C3 | one bad target among good ones | only that target fails |
| C4 | a target that never answers | only that target times out, within its budget plus grace |
| C5 | crash after some records | partial; settled targets kept; the rest unfinished |
| C6 | stop `cancel` | result within the grace; nothing delivered |
| C7 | stop `pause`, then resume with the checkpoint | no settled target runs again (tools declaring `checkpoint`) |
| C8 | recording egress sink | no connection outside the targets and the hosts derived from them |
| C9 | canary credential | the canary appears in no record, log, artifact or error |
| C10 | undeclared output, output flood | quarantined or capped; partial |
| C11 | provenance written by the tool | overwritten by the runtime |
| C12 | two tasks back to back | the second sees nothing of the first |
| C13 | per-host rate | measured rate at the sink within 10 % of the job limit |
| C14 | slow but alive | not stalled while records or CPU time grow |
| C15 | connector import with a cursor | the second run starts from the cursor; no duplicate records |
| C16 | unknown message, unknown job key | ignored, refused |

`sensortest.NewPlatform` is a fake platform: enrollment, claims with jobs
signed by a test root, heartbeats with injectable cancel, stop and pause,
result capture with batch and epoch checks, and a restart of the sensor under
test. A team building its own sensor runs the sensor suite against it.

### 6.3 Documentation outline ("Build a tool")

1. Concepts on one page: capability, descriptor, task, outcome, the seven rules.
2. Quickstarts: a CLI with no code, Go with `tool.Define`, any language over the adapter protocol.
3. Recipes: a list tool with JSON lines, a per-target tool, a connector with a cursor, a parser, a credentialed scan, artifacts, relations, a web-scoped crawler, retests.
4. Generated reference: `tool.yaml`, the job payload, adapter messages, the `execution` block, error classes, the capability taxonomy, common options.
5. Testing and certification.
6. The security model as a tool author sees it.
7. Versioning and deprecation.

## 7. Security

| Threat | Control |
|---|---|
| A hostile tool writes a checkpoint that poisons the next attempt, possibly on another sensor of the same tenant | the checkpoint is bound to the tenant, at most 64 KiB of JSON, sanitised, and covered by the next job's signed digest; a tool treats `task.State` as untrusted input (the kit fuzzes it); it never crosses tenants |
| A hostile sensor marks targets covered without scanning them | `targets[].ref` must lie within the job's targets; a `done` for a networked capability without any records or CPU time is downgraded; results from shared sensors are written at the shared trust level |
| Artifact upload abuse | the upload grant is bound to tenant, command and lease epoch; size and media type are capped by descriptor and policy; content-addressed; downloads are served as attachments, never inline |
| Credential leaks through output | jobs carry references only; values are resolved on the sensor and masked by value everywhere; the canary scenario C9; shared sensors receive no credentials |
| A cursor that rewinds or skips data | the cursor commits only with its batch; the previous cursor is kept; an administrator can reset it, audited |
| Silent drift between the platform's job and the SDK | one typed schema in ctis, strict decoding on both sides, golden tests |
| Relationship records that point at another tenant's assets | both ends must resolve inside the report or to the task's targets; the platform re-resolves identity within the tenant |
| A tool tries to keep a canceled job's results by claiming a different stop reason | the reason comes from the platform's heartbeat answer to the runtime; a tool cannot set it; cancel is fenced |

Every implementation PR adds negative tests: a checkpoint of another tenant is
not readable, a target ref outside the job is dropped, an artifact grant of
another command is refused, the canary credential is absent, an unknown job
key is refused.

## 8. What is removed

- SDK: the scanner, collector, parser, adapter, processor, enricher,
  connector, provider and the four scanner sub-interfaces; the scanner
  bridge (`toolcompat`); `Kit.AddScanner`, `AddCollector`, `AddParser` and
  `HandleRetest` (the command executor hook stays for platform control
  commands only); deprecated packages without importers (`retry`, `errors`,
  `health`, `metrics`, `options`, `pipeline`, `audit`, `credentials`, `mocks`,
  the unused gRPC transport, `enrichers`, `connectors`, `providers`); three of
  the four back-off implementations.
- Sensor: five of the six tool registries, parent-side parsing of raw tool
  output, its own politeness, version parsing and per-target loop.
- Platform: the second job builder and the duplicated payload keys; after one
  release train, the ad-hoc per-target report properties.
- Merged: `testkit` and `conformance` into `sensortest`; the per-target runners
  into `toolexec`.

## 9. Plan

| Phase | Content | Exit criterion |
|---|---|---|
| **P0 — one path** | `ctis/job` payload and schema; one error enum and the CTIS 1.7 `execution` block; stop reasons in the heartbeat answer; one platform job builder; execution ingest and coverage settlement from it; the artifact upload route; a native tool executor in the SDK runtime (no scanner bridge); `Task.Kind`, `Budget`, `State`; built-in tools registered once and parsed in the tool process | every built-in tool runs through `tool.Tool` only; artifacts and attempts reach the platform; one job structure end to end |
| **P1 — missing mechanisms** | checkpoints and import cursors (SDK and platform storage); batch delivery during a task and per-batch ingest; relationship records; credential references; the connector product on the standard; `pkg/sensortest` with scenarios C3–C16; removal of the legacy interfaces and packages; documentation and examples rewritten | a third-party tool and the connector pass `openctem tool test` with every scenario; no legacy interface remains |
| **P2 — completeness** | probed engine version and binary digest; offline job and result bundles; certification attestations over the kit's result; SDK v1.0.0 | the contract is frozen as v1.0.0 |

Merge order inside P0: ctis first; the SDK's `Task` fields; the platform
builder; the SDK runtime release; the sensor pins the released SDK; then the
platform reads the new block. A sensor change that needs an unmerged SDK change
stays a draft until the SDK change is on its main branch.

## 10. Not in v1

| Item | Why not now | Trigger |
|---|---|---|
| Container-image tool profile | needs the container executor backend | that backend lands |
| A published Python package | the one-file helper covers the protocol | the first external Python author |
| Declarative HTTP connector | one connector product today | three REST-only connectors |
| A pause verb in the tool protocol | pause is stop plus checkpoint | none |
| Long-lived daemon tools inside a sensor | chains of bounded tasks cover them | none |
| Offline bundles | contract fixed here; transport later | the first air-gapped installation (P2) |

## 11. Decisions

Adopted (2026-10-17): one interface and one runtime path, with the legacy path
removed after one release train; the typed job payload in ctis; the CTIS 1.7
`execution` block; one error enum with the action table; pause, restart,
imports and long runs as stop plus checkpoint plus re-planning; tools keep no
state across tasks; one test package; artifact upload bound to the command.

Open for the owner:

| # | Question | Recommendation |
|---|---|---|
| O1 | Does a user cancel keep settled results? | No: cancel discards (safe when the target was wrong); add "Stop and keep results" in the run view, which is a pause without resume |
| O2 | Which credential delivery ships first? | Sensor-local references (file, operating system keyring, then a vault); sealed platform-held credentials only on demand; never to shared sensors |
| O3 | When does the SDK become v1.0.0? | When P1 is merged and every built-in tool and the connector run on the standard |
| O4 | May the platform store opaque tool checkpoints? | Yes: per tenant, at most 64 KiB per task lineage and per import stream, kept for the run's retention (cursors until the connection is deleted) |
