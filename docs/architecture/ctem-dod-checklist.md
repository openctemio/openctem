# CTEM Definition-of-Done Checklist

The CTEM framework defines a closed-loop exposure-management model.
"100% CTEM" means every loop-closing invariant has a wire: something
that observes the upstream signal, does the work, and records the
outcome. This document tracks each invariant against the code that
proves it.

## Status snapshot

| Area | Gate | Status |
|------|------|--------|
| Q1 | F3, B1, B3, B4, B5 | ✅ integration tests locked in |
| Q2 | F4, B2, validation coverage SLO | ✅ integration tests locked in |
| Q3 | B6, runtime ingest, IOC auto-reopen | ✅ integration tests locked in |
| Q4 | Audit hash-chain, loop-closure SLOs | ✅ wired + tested |

Remaining open items are not framework gaps — they are ecosystem
breadth (more cloud connectors, more RLS tables) or UI consumers.

## Feedback invariants (F-edges)

| ID | Name | Wire | Test |
|----|------|------|------|
| F1 | Runtime detection → finding | `runtime_telemetry_handler` + IOC correlator | `tests/integration/ctem_ioc_invariant_test.go`, `ctem_runtime_gate_test.go` |
| F2 | Runtime evidence reopens | `internal/app/ioc/reopen_adapter.go` | `TestCTEM_B6_RuntimeMatchReopensClosedFinding` |
| F3 | priority_class → SLA deadline | `internal/app/sla/applier.go` | `TestCTEM_F3_*` |
| F4 | Proof-of-fix retest | `internal/app/validation/proof_of_fix.go` | `TestCTEM_F4_*` |

## Blocking invariants (B-edges)

| ID | Name | Wire | Test |
|----|------|------|------|
| B1 | Reclassification sweep | `controller.PriorityReclassifyController` | `TestCTEM_B1_*` |
| B2 | Compensating-control change triggers reclassify | `controller.ControlChangePublisher` | Q1 gate tests |
| B3 | Jira "Done" → verification scan | `internal/app/jira/rescan_hook.go` | `TestCTEM_B3_*` |
| B4 | SLA breach → notification outbox | `internal/app/sla/breach_outbox_adapter.go` | `TestCTEM_B4_*` |
| B5 | CTEM cycle review writes audit | `internal/app/audit_service.go` (hash-chain) | `TestCTEM_B5_*` |
| B6 | Runtime match → auto-reopen | `internal/app/ioc/correlator.go` | `TestCTEM_B6_*` |
| B7 | Scope delta mid-cycle | `internal/app/ctem_cycle_service.go` | completed separately |

## Observability invariants (O-edges)

| ID | Name | Status |
|----|------|--------|
| O1 | Stage-level Prometheus metrics | `internal/infra/telemetry` — ObserveStageIn/Out/Latency wired at Prioritization, Classification, Mobilization, Validation |
| O2 | Loop-closure SLO alerts | `setup/monitoring/alertmanager/alerts.yml` — CTEMPrioritizationStagnant, CTEMSLABreachSpike, CTEMJiraRescanSilent, CTEMSLABreachNotDelivered, CTEMStageLatencyTailHigh, CTEMCoverageSLOAtRisk |
| O3 | Audit hash-chain tamper-evidence | migration 000154 + `GET /audit-logs/verify` returns 409 on break |

## Anti-flap safeguards

- **Priority flood guard** — `internal/app/priority_flood_guard.go` caps
  top-class fan-out at 50/hour/tenant. Classification still records;
  only downstream side effects are suppressed.
- **Bulk-action guard** — `internal/app/bulk_action_guard.go` enforces
  500 rows/request + 10k rows/tenant/hour on bulk finding ops.

## Coverage gate

- **Validation coverage SLO** — `internal/app/validation_coverage.go`
  `Enforce(coverage, thresholds)` blocks cycle close when P0 or P1
  evidence coverage drops below threshold.
- Default thresholds: P0=100%, P1=100%, P2=80%, P3=unenforced.

## Hash-chain audit trail

- Migration 000154 adds `audit_log_chain` side table.
- Every `LogEvent` call appends a chain entry computed from
  `pkg/crypto/audit_chain.go` (SHA-256 over prev_hash + audit_id +
  payload + timestamp).
- `GET /audit-logs/verify` walks the chain and returns 409 with the
  offending entry on any break.

## Out of scope for this gate

| Task | Why not |
|------|---------|
| #339 GCP connector | Cloud Asset Inventory SDK + service-account credentials needed; not a loop invariant |
| #340 Azure connector | Azure Resource Graph SDK + credentials; not a loop invariant |
| #349 K8s in-cluster connector | k8s.io/client-go + kubeconfig; not a loop invariant |
| #350 Git-host connector | GitHub/GitLab/Bitbucket API tokens; not a loop invariant |
| #351 RLS remaining 62 tables | Blocked by #341 validation in production |
| #353 CTEM maturity dashboard UI | Frontend (ui/ Next.js codebase) |
| #356 Reclassification dry-run UI | Frontend |
| #363 Per-tenant KMS | Data-residency feature; orthogonal to CTEM loop |

## How to re-check at release time

```bash
# Every CTEM invariant has an integration test named TestCTEM_*:
go test ./tests/integration/ -run TestCTEM_ -v

# Q1 + Q2 + Q3 gate sets:
go test ./tests/integration/ -run "TestCTEM_(F3|F4|B1|B2|B3|B4|B5|B6|Coverage|Q3)" -v

# Hash-chain primitive:
go test ./pkg/crypto/ -run TestComputeAuditChainHash -v

# Priority flood-guard:
go test ./internal/app/ -run TestPriorityFlood -v
```

Any failure in the above = the gate reopens.
