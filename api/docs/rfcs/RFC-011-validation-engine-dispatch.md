# RFC-011 — Validation Engine: dispatch (make the "V" executable)

**Status:** Phase 1 (safe-check) shipped
**Related:** [`docs/architecture/validation-engine.md`](../architecture/validation-engine.md)

## Problem

OpenCTEM sells the 5-phase CTEM loop, but **Validation** was the only phase that
did not *do* anything. `POST /simulations/{id}/run` returns a canned in-process
result; the real engine contracts (`ValidationDispatcher`, `ProofOfFixService`,
`Selector`, `ValidationJob`) existed and were unit-tested but were never wired
to an agent. The evidence-ingest half (`POST /validation/evidence` →
persist → reconcile finding status → coverage SLO) was already live, waiting
for a producer.

## Goal

Let an operator (or automation) request a real, non-intrusive re-check of a
finding that runs on an agent and whose outcome moves the finding — reusing the
already-wired evidence pipeline, with the lowest-risk first cut.

## Design

- **Producer endpoint** `POST /api/v1/findings/{id}/validate` (JWT,
  `findings:write`) → `RunService.ValidateFinding`: resolve finding → asset →
  `Target`, pick an executor kind via `DefaultSelector` against the fleet's
  advertised kinds, build a `ValidationJob`, dispatch. Returns `202 {command_id}`.
- **Transport = tenant command.** `CommandDispatcher` marshals the job into a
  `CommandTypeValidate` command (migration `000184`) and enqueues it on the
  existing agent command queue. Chosen over the platform-job poll/result surface
  because that surface is **not currently wired on the API** (only
  `/platform/stats` exists); the tenant `/agent/commands` poll + `/complete`
  path is fully wired.
- **Return path = completion hook.** On `POST /agent/commands/{id}/complete`,
  `triggerValidationEvidence` maps a `validate` command's `{outcome,summary}`
  result into `validation.Evidence` and calls `EvidenceIngestService.Ingest`
  with the tenant **from the command** (authoritative), not the reporting agent.
  This avoids the `/validation/evidence` endpoint's tenant-from-agent constraint
  (which rejects cross-tenant platform agents) and reuses the wired ingest +
  redaction + status reconciliation + coverage SLO.
- **Round-1 execution = `safe-check` only** — non-intrusive TCP/TLS/HTTP
  reachability re-check (technique `T1046`). No Atomic Red Team / Caldera driver
  and no attacker-profile capability plumbing. Executor-kind routing is built so
  `nuclei` re-check is a follow-up, not a rewrite.

## What ships in Phase 1 (this PR)

API only: `CommandTypeValidate` + migration `000184`, `CommandDispatcher`,
`RunService`, the `POST /findings/{id}/validate` endpoint, the
`triggerValidationEvidence` completion hook, unit tests, and an E2E live guard
(`scripts/tests/test_e2e_validation_engine.sh`) that drives the full loop.

## Follow-ups

1. **Agent executor** — teach the agent to execute `validate` commands
   (safe-check probes reusing the SSRF-guarded target validation). The
   tenant-runner uses `sdk-go/pkg/core` with a fixed command-type switch, so
   this is an sdk-go release + agent bump.
2. **`nuclei` re-check kind** — re-run the finding's own template to confirm
   exploitability.
3. **Control-test / simulation correlation** — populate
   `validation_evidence.simulation_run_id` and link evidence to control tests.
4. **UI** — "Validate now" action + evidence timeline on the finding detail.
