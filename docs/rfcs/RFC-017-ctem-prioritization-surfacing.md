# RFC-017: CTEM Prioritization Surfacing & Loop Closure

**Status:** Proposed
**Author:** Platform
**Related:** RFC-011 (validation engine), RFC-015 (remediation groups), CTEM maturity audit (2026-07)

## Summary

OpenCTEM already computes a genuinely good CTEM priority — a deterministic
`priority_class` (P0–P3) with a human-readable reason, combining severity, EPSS,
KEV, asset criticality, crown-jewel status, reachability, compensating controls
and business impact. **The problem is not the brain; it is the last mile and the
seams.** The computed priority is not sortable or filterable, three other
"scores" compete with it, two Scoping signals never reach it, and the
persisted reachability field is dead code. This RFC surfaces the priority as the
organizing principle for "what to work on next", closes the two live seams, and
rationalises the competing scores — improving an engine that already runs rather
than rewriting it.

## Current state (verified in code)

### The real engine
`ClassifyPriority(PriorityContext)` — `pkg/domain/vulnerability/priority.go:93`,
orchestrated by `PriorityClassificationService` (`internal/app/finding/priority_classification.go`),
runs at **ingest** (`processor_findings.go:1614`), on **reclassify sweeps**
(`reclassify/reclassifier.go:161`, triggered by EPSS/KEV/rule/control/asset
changes), and **on-demand** (`vulnerability_handler.go:2132`). Output:
`priority_class` + `priority_class_reason` (+ tenant override rules).

Inputs **actually used**: severity, EPSS, KEV, asset criticality, asset exposure
→ reachability (derived), crown-jewel, compensating controls, attack-path oracle
(optional), `data_exposure_risk`, `compliance_impact`.

### The four problems

1. **Priority is not sortable or filterable.**
   `FindingAllowedSortFields()` (`repository.go:525`) allows only
   `severity,status,source,created_at,updated_at,file_path,tool_name`.
   `FindingFilter` (`repository.go:548`) has no priority/KEV/EPSS/reachability
   field. Default list sort is `created_at DESC` (`defaultSortOrder`,
   `asset_repository.go:22`). → Operators see findings by creation date, not
   P0-first. The prioritization dies at the last mile.

2. **Four competing scores, none unified.**
   - `priority_class` P0–P3 — the real one.
   - AI-triage `risk_score` + `priority_rank` — separate `ai_triage_results`
     table, **never written back to the finding** (advisory only).
   - CVE catalogue `RiskScore()` 0–10 (`entity.go:525`) — on the global CVE, not
     the finding.
   - SARIF `rank` 0–100 — pass-through from the scanner, plus assignment-rule
     override; not derived.
   - (The asset-grouped list uses a *fifth* ordering: asset
     `criticality → sla_rank → risk_score`, `finding_repository.go:1331`.)

3. **Two Scoping signals are disconnected.**
   - **Attacker Profiles** (`pkg/domain/attackerprofile/`) — entity + handler +
     routes + table, but **zero readers** in prioritization. CRUD-only.
   - **Business Service model** (`business_services` + `business_service_assets`,
     migration 000152) — rich (per-service criticality, PII/PHI, RPO/RTO) but
     **no code reads the asset↔service mapping** for scoring or SLA, despite
     `module/dependency.go:111` claiming "impact scoring is weighted by
     business-service mapping". (The finding-level business bump from CTIS
     `data_exposure_risk`/`compliance_impact` *is* wired — this is only about the
     Business Service entity.)

4. **Reachability persisted field is dead code.**
   `Finding.SetReachability` (`priority.go:297`) has **no callers**;
   `is_reachable`/`reachable_from_count` columns are never populated. The signal
   still reaches scoring, but only via an ephemeral derivation from asset
   exposure + the attack-path oracle at classify time — so it can't be filtered,
   explained, or shown.

## Goals

- Make `priority_class` the sortable/filterable, default ordering of findings.
- Make the priority **explainable** in the UI (reason already exists).
- Persist reachability so it is queryable + explainable.
- Connect the two disconnected Scoping signals (Attacker Profiles, Business
  Service mapping) into `PriorityContext`.
- Reduce four competing scores to one canonical priority + an advisory overlay.
- Gate closure on validation; sync ownership across the Mobilization seam.

## Non-goals

- Rewriting the classification ladder (it is sound).
- Replacing AI triage (kept as an advisory overlay).
- Real BAS execution (RFC-012) — out of scope here.

---

## Phase 1 — Surface priority: sort + filter + default P0-first (highest leverage, low effort)

**api**
- `pkg/domain/vulnerability/repository.go`
  - `FindingAllowedSortFields()`: add
    `"priority_class": "priority_class"` (text `P0..P3` sorts ASC = P0 first),
    `"epss_score": "epss_score"`, `"is_in_kev": "is_in_kev"`.
  - `FindingFilter`: add `PriorityClasses []string`, `IsInKEV *bool`,
    `EPSSMin *float64`, `IsReachable *bool`.
- `internal/infra/postgres/finding_repository.go`
  - WHERE builder: honour the new filter fields (parameterised).
  - New `defaultFindingSort = "priority_class ASC, <severity CASE> ASC, created_at DESC"`
    for the flat list (keep `created_at` fallback for other entities).
- `internal/infra/http/handler/vulnerability_handler.go` (`ListFindings`) — parse
  `priority_class`, `is_in_kev`, `epss_min`, `is_reachable` query params into the
  filter (mirror the `Severities/Statuses/Sources` parsing pattern at
  `finding_actions_handler.go:457`). Also expose them to the MCP list tool
  (`mcp_tools.go`).

**ui**
- Findings list (`src/app/(dashboard)/findings/page.tsx`): add a **Priority**
  filter (P0–P3) + KEV/Reachable toggles next to Status/Source; add `priority_class`
  to the sortable columns; default the table to CTEM-priority order. Extend
  `FindingApiFilters`.

**tests:** repository sort/filter unit tests; handler param-parse test; ordering
integration test (P0 rows first).

## Phase 2 — Explainability + persist reachability

**api**
- Persist reachability: call `SetReachability(...)` from `buildPriorityContext`
  (`priority_classification.go:~521-547`) with the derived value + count, so
  `is_reachable`/`reachable_from_count` become real columns (feeds P1's
  `IsReachable` filter). Alternative if we choose not to persist: delete the dead
  setter — but persisting is preferred (query + explain + UI).
- Response already carries `priority_class_reason` (`vulnerability_handler.go:442`).

**ui**
- Finding header/overview: render `priority_class` as a first-class badge with the
  reason on hover/expand ("P0 — KEV + reachable + crown-jewel"). Show
  reachability + its source (asset exposure / attack path).

**tests:** classify sets reachability columns; reason surfaces in response.

## Phase 3 — Close the two Scoping seams

**api — Attacker Profiles → priority**
- Add an optional reader in `buildPriorityContext`: when a finding's
  technique/CWE/asset matches an **active** attacker profile, set a new
  `PriorityContext` signal (e.g. `MatchesActiveAdversary bool`) that the ladder
  uses as a bump (never above P0). Wire nil-safe like the reachability oracle.

**api — Business Service mapping → business bump**
- Resolve the finding's asset → `business_service_assets` → service criticality /
  compliance scope; feed `applyBusinessImpactBump` (today only CTIS
  `data_exposure_risk`/`compliance_impact` drive it). Correct the
  `dependency.go:111` doc to match reality.

**tests:** matrix — adversary-match bumps; business-service criticality bumps;
neither regresses when unwired (nil-safe).

## Phase 4 — Rationalise the competing scores (clarity/honesty)

- Make `priority_class` (+ reason) the single canonical priority in every finding
  surface.
- AI triage: relabel as **advisory** (badge "AI"), or add an explicit,
  human-in-the-loop path to accept its suggestion into `priority_class` — no
  silent second number.
- Remove SARIF `rank` and CVE `RiskScore` from finding-facing UI (keep `RiskScore`
  on the CVE catalogue where it belongs).
- Reconcile the asset-grouped ordering (`finding_repository.go:1331`) to consider
  `priority_class` (or document why it intentionally differs).

## Phase 5 — Loop closure (Mobilization + measurement)

- **Validation-gated closure:** default every resolve (direct, group RFC-015,
  campaign) to `fix_applied`; let validation/rescan/auto-resolve promote to
  `resolved`. (`fix_applied` is already the group/campaign default.)
- **Assignment sync Campaign↔Finding:** creating/assigning a campaign propagates
  the owner to member `finding.assignee`; roll finding assignees up to the
  campaign. (Today `campaign.SetAssignment` and `finding` assignee are
  independent — `remediation_campaign.go:225` vs `assignment/engine.go`.)
- **Cut synthetic surfaces:** remove or wire the 4 `/remediation` sub-tabs
  (`tasks/priority/overdue/teams`) that render `useDashboardStats` under
  remediation labels; align "task"→"campaign" naming.
- **Loop metrics:** CTEM Maturity page measures MTTR, % validated closures,
  scanning coverage, SLA backlog — the loop's health, not vanity counts.

---

## Execution order

**P1 → P2 → P3 → P5 → P4.** P1+P2 are small and change daily operator behaviour
(ship first, one api PR + one ui PR). P3 is the core CTEM seam-closure. P5 cleans
Mobilization. P4 (multi-score product decision) last.

## Seam status (reference)

| Signal | Verdict | Feeds priority today? |
|---|---|---|
| Severity / EPSS / KEV | WIRED | yes |
| Asset criticality / Crown jewel | WIRED | yes |
| Compensating controls | WIRED | yes (reduces) |
| Business impact (CTIS finding-level) | WIRED | yes (bump) |
| Reachability (signal) | HALF (derived, not persisted) | yes, ephemeral |
| Reachability (persisted field) | DEAD (`SetReachability` unused) | no |
| Attacker Profiles | DISCONNECTED (CRUD-only) | no → P3 |
| Business Service model | DISCONNECTED (doc lies) | no → P3 |
| AI-triage risk_score | ISOLATED (separate table) | no → P4 |
| CVE `RiskScore` / SARIF `rank` | PARALLEL/pass-through | no → P4 |

## Backward-compatibility & risk

- P1 default-sort change is display-only; existing filters keep working. Guard the
  new sort behind the same allow-list (no SQL injection surface).
- Reachability persistence (P2) is additive columns already present in the schema.
- P3 readers are nil-safe/optional (no behaviour change until wired), mirroring the
  existing `reachabilityOracle` pattern.
- P4 is the only user-visible removal (competing scores) — stage behind review.

## Decision log

- **Improve, don't rewrite:** the P0–P3 ladder is CTEM-correct; the gap is
  surfacing + seams, confirmed by two independent code audits.
- **One canonical priority:** `priority_class` + reason; AI triage stays advisory.
- **Persist derived reachability** rather than delete the dead field — enables
  filter + explainability.
