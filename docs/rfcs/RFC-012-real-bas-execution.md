# RFC-012 — Real BAS / attack-simulation execution (make the "V" not-synthetic)

> Status: **Proposed** (Phase 0 — honesty fix — shipped alongside this doc)
> Depends on: [RFC-011](RFC-011-validation-engine-dispatch.md) (validation dispatch)

## Problem

OpenCTEM's CTEM maturity assessment scored **Validation 2.1/5 — the weakest
phase**. The root cause is that Breach-and-Attack-Simulation (BAS) is **synthetic**:

`internal/app/compliance/simulation.go:executeSimulationTechnique` decides a
run's outcome purely from *configuration*, with **no execution**:

```go
detectionSource, _ := config["detection_source"].(string)
if detectionSource != "" {
    detection = fmt.Sprintf("Validated against %s", detectionSource)
    result = simulation.RunResultDetected      // ← "control validated" with zero execution
}
```

So a simulation reports **`detected` — a passing security control** whenever an
operator merely *typed a SIEM/EDR name into a config field*. The technique is
never run; the control is never exercised. `RunSimulation` is synchronous and
returns a "completed, detected" run immediately. This is worse than a missing
feature: it manufactures **false security assurance** ("your controls caught
this attack") that no evidence backs.

Related gap flagged by the assessment: **validation↔simulation correlation is
missing** — `validation_evidence.simulation_run_id` exists end-to-end (column,
repo write, ingest param, API response) but **nothing server-side ever sets
it**.

## What already exists (and can be reused)

RFC-011 built a **real, async, agent-dispatched execution path** for
finding-level proof-of-fix, all shipped:

- `validation.RunService` → `validation.CommandDispatcher` enqueues a
  `CommandTypeValidate` platform job carrying `{technique, target, executor_kind,
  timeout}` (`internal/app/validation/dispatcher.go`).
- The **agent** has a real executor (`agent/internal/executor/validation.go`)
  that runs **safe-check probes** (TCP/TLS/HTTP reachability) behind the same
  SSRF/RFC1918 guard the scanners use, and returns an `outcome`
  (`detected`/`not_detected`/`error`).
- `CommandHandler.Complete` → `triggerValidationEvidence` maps the agent's
  result into `validation.Evidence` and calls
  `EvidenceIngestService.Ingest(ctx, tenantID, findingID, simRunID, ev)`.
- `Ingest`'s **`simRunID *shared.ID` parameter already flows** to
  `validation_evidence.simulation_run_id` (`evidence_store.go`) — it is simply
  passed `nil` today.

So "make BAS real" is mostly **wiring simulations onto the RFC-011 rails**, not
building an execution engine from scratch.

### Key constraint discovered

`EvidenceIngestService.Ingest` **requires a non-zero `findingID`** (tenant guard
+ FK). It is *finding-centric*. Therefore:
- A simulation that **targets a finding** (proof-of-fix / control re-test) can
  reuse the evidence path directly and set `simulation_run_id` for correlation.
- A **standalone BAS run** (no finding) must persist its outcome to the
  `simulation_runs` table via its own completion path — it cannot borrow the
  finding-scoped evidence ingest.

## Design

### Run model: synchronous-fabricated → asynchronous-dispatched

A real technique runs on an agent; the API cannot synchronously "know" the
outcome. `RunSimulation` becomes a **dispatcher**:

1. Resolve the simulation's **technique** and **target** (a target asset's
   address). Decide the **executor kind** via the RFC-011 `Selector`
   (`safe-check` for T1046/T1590/T1595; `nuclei` later).
2. If a live executor kind is available and the target is network-addressable:
   create the `SimulationRun` in **`running`**, enqueue a `validate` command
   whose payload also carries `simulation_run_id`, persist the run, return it
   `running` (HTTP 202).
3. A **completion hook** (sibling of `triggerValidationEvidence`, keyed off the
   payload's `simulation_run_id`) finalizes the run: map `outcome →
   RunResult` and `SimulationRun.Complete(...)`; when the simulation is also
   finding-scoped, record `Evidence` with `simulation_run_id` set (closing the
   correlation gap).
4. If **no** live executor fits (technique not safe-checkable, no network
   target, `dry_run`): do **not** fabricate a detection — see Phase 0.

Outcome mapping (safe-check reachability semantics):

| agent outcome | RunResult | meaning |
|---------------|-----------|---------|
| `not_detected` | `prevented` | target not reachable — control/segmentation held |
| `detected` | `bypassed` | target reachable — technique would succeed |
| `error`/refused | `error` | guard refused / bad target |

(Reachability is a *coarse* control signal; richer detection/prevention
semantics arrive with the telemetry-correlation phase below.)

### Technique → executor routing

Reuse `validation.DefaultSelector`. Round 1 supports **safe-check** only
(reachability-style techniques). `nuclei` re-check and Atomic-Red-Team style
execution are later kinds behind the same `Selector` seam — no rework.

### Correlation (validation ↔ simulation)

Populate `validation_evidence.simulation_run_id` from the command payload in the
completion hook. This links every piece of evidence to the BAS run that produced
it, powering coverage KPIs and the "what did this simulation actually prove"
view.

## Phases

- **Phase 0 — honesty (this PR):** stop reporting fabricated `detected`. The
  synthetic path is relabeled **explicitly simulated / unverified**
  (`verified:false`, `execution_mode:"simulated"`, detection text
  "simulated — not live-validated") so operators are not told a control was
  validated when nothing ran. No behavior the UI depends on is removed; the
  misleading claim is. Low-risk, api-only, no agent change.
- **Phase 1 — real safe-check dispatch:** `RunSimulation` dispatches a real
  `validate` command for network-addressable, safe-checkable simulations; async
  completion hook finalizes the run + sets `simulation_run_id`. Reuses the
  shipped agent executor — **api-only**. Standalone (finding-less) runs finalize
  via the `simulation_runs` table.
- **Phase 2 — richer executors + correlation to controls:** add `nuclei` kind;
  correlate simulation outcomes to `control_test` records; consume runtime
  telemetry/IOC (B6) as a real *detection* signal (vs bare reachability).
- **Phase 3 — campaigns:** multi-step chains dispatched as ordered jobs.

## API / UI impact

- `POST /api/v1/simulations/{id}/run` returns **202 + a `running` run** in
  Phase 1 (was 200 + completed). The UI must poll the run to completion (same
  pattern as scans). Phase 0 keeps the current sync response.
- No breaking change to the `validation_evidence` / `simulation_runs` schemas —
  `simulation_run_id` already exists.

## Testing

- Phase 0: unit-assert the synthetic path never returns `detected` with
  `verified:true`, and that output carries `execution_mode:"simulated"`.
- Phase 1: dispatcher builds a `validate` command carrying `simulation_run_id`;
  completion hook maps `outcome → RunResult` + finalizes the run; live e2e via
  the `_e2e_common.sh` harness (enqueue → complete as agent → assert the run
  finalized + a correlated `validation_evidence` row).

## Rollout

Each phase is a separate PR → `develop` (agent → `main` per repo convention),
referencing this RFC. Phase 0 ships with this document.
