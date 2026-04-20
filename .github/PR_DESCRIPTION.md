# CTEM feedback loops Q1+Q2+Q3+Q4 gates + B6 runtime loop

## Summary

Closes the CTEM framework loop to **100% of the Definition-of-Done
checklist** for backend-feasible invariants. Three quarterly gates
now have end-to-end integration tests; Q4 gate ships the audit
hash-chain, loop-closure SLO alerts, and validation coverage
enforcement.

See `docs/architecture/ctem-dod-checklist.md` for the invariant-by-
invariant map of wire → test.

## Invariants wired + tested

| Edge | Name | File | Test |
|------|------|------|------|
| F1, F2 | Runtime detection reopens findings | `internal/app/ioc/correlator.go` + `reopen_adapter.go` | `TestCTEM_B6_*`, `TestCTEM_Q3_*` |
| F3 | priority_class → SLA deadline | `internal/app/sla/applier.go` | `TestCTEM_F3_*` |
| F4 | Proof-of-fix retest | `internal/app/validation/proof_of_fix.go` | `TestCTEM_F4_*` |
| B1 | Reclassification sweep | `controller.PriorityReclassifyController` | `TestCTEM_B1_*` |
| B2 | Compensating-control change → reclassify | `controller.ControlChangePublisher` | Q1 gate |
| B3 | Jira "Done" → verification scan | `internal/app/jira/rescan_hook.go` | `TestCTEM_B3_*` |
| B4 | SLA breach → notification outbox | `internal/app/sla/breach_outbox_adapter.go` | `TestCTEM_B4_*` |
| B5 | CTEM cycle close writes audit | audit hash-chain (migration 000154) | `TestCTEM_B5_*` |
| B6 | Runtime match → auto-reopen | `internal/app/ioc/` | `TestCTEM_B6_*` |
| O1 | Stage-level Prometheus metrics | `internal/infra/telemetry` | runtime |
| O2 | Loop-closure SLO alerts | `setup/monitoring/alertmanager/alerts.yml` | — |
| O3 | Audit hash-chain tamper-evidence | migration 000154 + `/audit-logs/verify` | `TestCTEM_B5_AuditChainDetectsTamper` |

## New features

- **Runtime telemetry ingest** (`POST /telemetry-events`) — batch EDR/XDR
  event ingest from endpoint agents. Migration 000155.
- **IOC catalogue** — full CRUD (`/iocs`) + correlator that auto-reopens
  closed findings on runtime match. Migration 000156.
- **Audit hash-chain** — every LogEvent call appends a SHA-256 chain
  entry. `GET /audit-logs/verify` returns 409 on tamper. Migration 000154.
- **Executive summary PDF export** — `?format=html` returns a
  print-ready report; users save-as-PDF through browser.
- **Recon adapter** — subdomain/DNS/port/http_probe/url_crawl outputs
  plug into the unified adapter path.
- **Priority flood guard** — anti-flap cap on top-class downstream
  fan-out (configurable `ProtectedClass`).
- **CTEM alert rules** — 6 alerting rules for loop-closure SLOs.

## Security fixes

- **CodeQL go/uncontrolled-allocation-size** (High) — 4 handlers used
  `make([]T, 0, perPage)` where `perPage` was user-controlled. Fixed by
  `parseQueryIntBounded(s, default, min, MaxPerPage=100)` at the parse
  site so CodeQL's data-flow analysis sees the cap statically.
- **RLS shadow-mode policies** — 145 tenant-scoped tables now have
  `tenant_isolation` policies defined. RLS is not enabled yet;
  rollout is per-table per `docs/architecture/rls-rollout.md`.
- **Audit hash-chain** — tamper-evident audit log chain.

## Code quality

- **Magic-naming sweep** — 11 hardcoded strings extracted behind
  named constants (workflow/scan RunStatus, platform enum, role
  constants, export format, license NOASSERTION, CI platform switch).
- **Doc drift fix** — 8 markdown files reconciled with code (Go
  version 1.26+, migration count 156, new endpoints documented).
- **Dead code removed** — `cappedPerPage` helper (0 callers), stale
  `Q1` fixture name, `P0FloodGuard` → `PriorityFloodGuard` with
  configurable class.
- **Spelling consistency** — `Normalise/Normalised/value_normalised` →
  `Normalize/Normalized/value_normalized` to match the rest of the
  codebase (`normalizeSnippet`, `normalizeURL`).

## Migrations

- `000154_audit_hash_chain` — audit_log_chain side table
- `000155_runtime_telemetry` — runtime_telemetry_events
- `000156_iocs` — iocs + ioc_matches
- `000157_rls_policies_shadow` — RLS policies on top 20 tables
- `000158_rls_policies_shadow_remaining` — RLS policies on remaining
  125 tables

Migration count: **156 → 158** (total). All shadow-mode migrations
are idempotent (DROP POLICY IF EXISTS + CREATE) and have no runtime
effect until RLS is enabled per table.

## Test plan

- [x] Build clean: `GOWORK=off go build ./...`
- [x] Full unit + integration suite passes
- [x] 56 CTEM-specific tests pass (`go test ./tests/integration/ -run TestCTEM_`)
- [x] 11 recon adapter tests pass
- [x] 11 IOC correlator unit tests pass
- [x] 5 Q3 gate integration tests pass
- [x] 5 B6 integration tests pass
- [x] 4 F4 integration tests + 5 coverage-SLO tests pass
- [x] `go vet` clean on new packages
- [x] `gofmt -l` clean on new packages
- [ ] Migrate 000154–000158 apply cleanly on staging DB
- [ ] Smoke test on staging: POST /iocs → POST /telemetry-events with
      matching IP → verify finding reopened + ioc_match row + audit
      chain intact + /audit-logs/verify returns 200
- [ ] Verify `/dashboard/executive-summary/export?format=html` renders
      a readable print layout in Chrome + Firefox

## Out of scope (tracked as separate tasks)

| Task | Why deferred |
|------|---------------|
| #339 GCP connector | Needs `cloud.google.com/go/asset` SDK + service account |
| #340 Azure connector | Needs Azure SDK + tenant credentials |
| #349 K8s in-cluster connector | Needs `k8s.io/client-go` + kubeconfig |
| #350 Git-host connector | Needs GitHub/GitLab/Bitbucket API tokens |
| #353 CTEM maturity dashboard UI | Frontend codebase (`ui/`) |
| #356 Reclassification dry-run UI | Frontend codebase |
| #363 Per-tenant KMS | Needs KMS backend choice + cryptographic review |

These are ecosystem breadth, not framework gaps. The CTEM loop is
complete without them.

## Reviewer notes

1. **Read order** — start with `docs/architecture/ctem-dod-checklist.md`
   for the invariant map, then `docs/architecture/rls-rollout.md` for
   the RLS rollout procedure.
2. **Tests first** — every commit that claims a wire has a matching
   `TestCTEM_*` integration test. If a claim doesn't trace back to a
   test, flag it.
3. **RLS safety** — policies are created but RLS is NOT enabled.
   Migration 000157/158 have zero runtime effect. RLS is enabled
   per-table in follow-up ops migrations after validation.
4. **Migration edit in place** — `000156_iocs.up.sql` was edited after
   an earlier commit to rename `value_normalised` → `value_normalized`.
   This is safe because the migration has only run in dev/test DBs.
   Reviewer should `make reset-db` before pulling.

## Commits (32)

See `git log --oneline origin/main..HEAD`. Organised chronologically:
CTEM loop primitives → integration tests → audit hash-chain →
runtime telemetry + IOC → bootstrap wiring → CodeQL + RLS hardening
→ naming/doc cleanup.
