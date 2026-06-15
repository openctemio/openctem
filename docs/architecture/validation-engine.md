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

## Not yet shipped (deferred)

- **Synchronous dispatcher** — `ValidationDispatcher`/`ProofOfFixService.Retest`
  exist (queue a job, block for the agent's reply) but are not wired to a
  production agent queue. The ingest endpoint is the activation seam that makes
  Validation functional today: the agent runs the technique on its own schedule
  and POSTs back, rather than the API blocking on a dispatch.
- **Pentest retest wiring** — `POST /pentest/findings/{id}/retests` does not yet
  call the ingest/proof-of-fix path.
- **Coverage SLO enforcement** at cycle-close (`coverage.go` exists, not gated).
- **`AgentCapability` production impl** (executor-kind discovery from agent
  registrations).
