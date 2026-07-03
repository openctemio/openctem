# Validation Engine (CTEM Stage-4)

> How OpenCTEM records validation/proof-of-fix evidence and reconciles a
> finding's status from the result. The platform is an **orchestrator** — the
> agent in the tenant's network executes the technique; the API persists the
> evidence and applies the outcome.

## What "Validation" means here

CTEM Stage-4 answers: *did the fix actually hold, and is the exposure really
gone?* Instead of trusting a status change, OpenCTEM records **Evidence** — the
result of re-running a technique against the finding's target — and moves the
finding accordingly.

```
agent executes technique ──► POST /api/v1/validation/evidence ──► persist (redacted)
                                                                      │
                                                                      ▼
                                                    reconcile finding status
                                          not_detected → resolved (fix stood)
                                          detected     → in_progress + notify
                                          else         → no status change
```

## Shipped (this MVP)

| Piece | Where |
|-------|-------|
| Evidence + Outcome + Target data shapes | `internal/app/validation/executor.go` |
| Redaction + persistence facade | `internal/app/validation/evidence_store.go` |
| **Ingest service** (record + reconcile) | `internal/app/validation/evidence_ingest.go` (`EvidenceIngestService`) |
| Outcome→status mapping (shared) | `internal/app/validation/proof_of_fix.go` (`applyOutcomeToFinding`) |
| Postgres persistence | `internal/infra/postgres/validation_evidence_repository.go`, migration `000178_validation_evidence` |
| HTTP endpoints | `internal/infra/http/handler/validation_handler.go` |
| Routes | `internal/infra/http/routes/validation.go` |

### Endpoints

- `POST /api/v1/validation/evidence` — **agent API-key auth.** An agent submits
  the result of a validation/proof-of-fix run for a finding. The tenant is taken
  from the authenticated agent (`AgentFromContext`), **never** the body, so a
  compromised agent cannot write into another tenant. Returns `202 Accepted`
  with the evidence id and whether the finding's status changed.

  Body:
  ```json
  {
    "finding_id": "<uuid>",
    "executor_kind": "safe-check",
    "technique": "T1046",
    "outcome": "not_detected",
    "summary": "exposure no longer reproduces",
    "target": { "type": "web_url", "address": "https://..." },
    "simulation_run_id": "<uuid?>",
    "artifacts": ["<attachment-id>"],
    "raw_meta": { }
  }
  ```

- `GET /api/v1/findings/{id}/evidence` — **JWT auth, `findings:read`.** Lists the
  evidence recorded for a finding (newest first) for the finding detail page.

### Guarantees

- **Tenant isolation** — evidence is scoped to the agent's tenant; the finding
  must exist *within that tenant* before any evidence is recorded (guards
  against cross-tenant finding ids that the FK alone would not catch).
- **Secret redaction** — `Summary` and `RawMeta` stdout/stderr are scrubbed for
  common secret patterns before persistence (defence-in-depth; the agent should
  not capture secrets, but Atomic Red Team stdout can).
- **Evidence is the source of truth** — it is always persisted; if the finding
  cannot legally transition from its current state (e.g. already closed) that is
  logged but not fatal, and the recorded evidence still surfaces.
- **Outcome mapping has one home** — `applyOutcomeToFinding` is shared by the
  ingest path and the `ProofOfFixService.Retest` (dispatch) path.

## Dispatch (producer side) — RFC-011 MVP

The ingest side above records evidence that arrives "out of band". RFC-011 adds
the **producer**: an operator (or automation) can *ask* for a validation run,
and the result flows back through the same ingest path — no new agent HTTP
surface.

```
POST /api/v1/findings/{id}/validate  (JWT, findings:write)
      │  RunService.ValidateFinding: resolve finding → asset → Target,
      │  Selector picks safe-check, build ValidationJob
      ▼
CommandDispatcher → command (type=validate, tenant-scoped) → agent poll queue
      │  agent runs the safe-check probe, reports {outcome,summary} on
      │  POST /agent/commands/{id}/complete
      ▼
CommandHandler.Complete → triggerValidationEvidence(cmd)
      │  maps result → Evidence, tenant taken from the COMMAND (authoritative)
      ▼
EvidenceIngestService.Ingest → persist (redacted) + reconcile finding status
```

| Piece | Where |
|-------|-------|
| `validate` command type | `pkg/domain/command/entity.go` (`CommandTypeValidate`), migration `000184_command_type_validate` |
| Async dispatcher (job → command) | `internal/app/validation/dispatcher.go` (`CommandDispatcher`) |
| Producer service (finding → job) | `internal/app/validation/run.go` (`RunService.ValidateFinding`) |
| Producer endpoint | `POST /api/v1/findings/{id}/validate` (`FindingActionsHandler.RequestValidation`) |
| Result → evidence hook | `internal/infra/http/handler/command_handler.go` (`triggerValidationEvidence`) |

**Why the completion hook, not a direct agent POST to `/validation/evidence`:**
that endpoint requires a *tenant* agent (takes tenant from the agent). Routing
the result through the command-completion hook lets the tenant come from the
**command** — the single authoritative source — and reuses the wired
poll/ack/start/complete queue instead of the not-yet-wired platform-job
transport.

**Round-1 scope:** only the `safe-check` executor kind (non-intrusive TCP/TLS/
HTTP reachability re-check, technique `T1046`). `Selector`/`DefaultSelector`
already prefer it and gate the riskier kinds behind an attacker profile; the
routing is built so `nuclei` re-check slots in next without rework.

## Not yet shipped (deferred)

- **Agent-side executor** — the API enqueues `validate` commands, but the agent
  binary does not yet execute them (the tenant-runner uses `sdk-go/pkg/core`
  with a fixed command-type switch; adding `validate` there is a follow-up
  sdk-go release + agent bump). Until then the loop is driven by the E2E harness
  / any client that completes the command with an outcome.
- **Synchronous dispatcher** — `ValidationDispatcher`/`ProofOfFixService.Retest`
  (block for the agent's reply) remain unused; the async producer above is the
  functional path.
- **Pentest retest wiring** — `POST /pentest/findings/{id}/retests` does not yet
  call the ingest/proof-of-fix path.
- **Coverage SLO enforcement** at cycle-close (`coverage.go` exists, not gated).
- **`AgentCapability` production impl** (executor-kind discovery from agent
  registrations).
