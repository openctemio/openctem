# Module coupling & the path to feature-toggleable modules

> Question this answers: **"If we later don't need a module (e.g. pentesting),
> can the system keep running instead of dying?"** — plus a concrete, phased
> plan to get there.

## TL;DR

- The **domain layer is cleanly layered** — core (`asset`, `vulnerability`,
  `component`) imports only `shared`; features depend on core, not the reverse;
  **no import cycles**.
- The **data layer is almost clean**: exactly **one** core→feature foreign key
  exists — `findings.pentest_campaign_id → pentest_campaigns` (migration 000095,
  CASCADE in 000171). Every other cross-link (45+) is the healthy feature→core
  direction; `assets` has zero feature FKs.
- The **composition root is monolithic**: `NewRepositories` builds ~110 repos
  and `NewServices` ~89 services **unconditionally**. There are env/config
  toggles (AI-triage, OAuth, ingest mode…) but **no per-module on/off**.
- The **`Module`/`TenantModule` system now gates routes at runtime** (Phase 1
  shipped). Beyond driving the sidebar and a notification-event filter, the
  `middleware.ModuleGate.RequireModule(moduleID)` middleware wraps **26 route
  groups** in `internal/infra/http/routes/routes.go` and returns
  `403 MODULE_NOT_ENABLED` for a tenant's explicitly-disabled module. It is
  **fail-open** (nil gate / missing tenant / core module / lookup miss → allowed)
  — a feature gate, not a security boundary. Disabling a module in
  `tenant_modules` now hides it from the sidebar **and** 403s its gated
  endpoints, per tenant, at runtime.
- A module can also still be **disabled deployment-wide by leaving its handler
  nil** (all-or-nothing). What remains unbuilt is per-*deployment* optional
  *construction* by config (Phase 2) and un-weaving pentest from core (Phase 3).
- **Pentest is the one hard-to-remove feature** — it was deliberately merged into
  the shared `findings` table, so ~12 hooks live in core (`vulnerability.Finding`
  fields/methods, `FindingRepository` branches, `guardNotPentestManaged` on
  generic mutation paths, permission constants, tenant settings). Everything else
  is a comparatively clean bolt-on.

## The four coupling dimensions

| Dimension | State | Evidence |
|-----------|-------|----------|
| **Build-time (imports)** | Domain clean; one app-layer wrinkle: core `internal/app/finding` imports features `aitriage` + `validation`, but only via **optional nil-guarded setters** (`SetAITriageService`, `autoValidator == nil` bail) — compiles-against, runs-without. `workflow` is the orchestration hub (imports finding/aitriage/pipeline/scan). No cycles. | `finding/vulnerability_service.go:45`, `actions.go:163` |
| **Wiring (composition root)** | Monolithic + unconditional. ~110 repo fields, ~89 service fields, all built in one pass. Conditionals are **env-driven, not module-driven**. No build tags. | `cmd/server/repositories.go`, `services.go` |
| **Data (DB FKs)** | **One** core→feature FK: `findings.pentest_campaign_id`. All other 45+ links feature→core. | `migrations/000095`, `000171` |
| **Runtime (module gating)** | **Shipped (Phase 1).** `middleware.ModuleGate.RequireModule(moduleID)` gates **26 route groups**, returning `403 MODULE_NOT_ENABLED` for a tenant's explicitly-disabled module; fail-open, 60s-TTL cache invalidated on toggle. `tenant_modules.is_enabled` now drives both the sidebar and route enforcement. | `middleware/module_gate.go`, `routes/routes.go` (26 `RequireModule(...)` sites), `bootstrap_handler.go:243` |

## What already helps (don't rebuild)

- **Route registration is nil-guarded** — 127 `!= nil` checks across
  `routes/*.go`; each feature has its own `register<Feature>Routes` behind
  `if h.<Feature> != nil`. Leaving a handler nil cleanly omits its routes.
- **Optional setter wiring** — services expose `SetX()` that may be skipped
  (`SetAssignmentApplier`, `SetRemediationKeyApplier`, `SetAuditService`…).
- **Notification outbox** decouples producers (finding/exposure/sla/workflow)
  from integration senders — cross-module reactions without imports.

## Removability by module (the litmus test)

- **Clean-ish bolt-ons** (delete own tables + feature→core FKs; core untouched):
  compliance, simulation, validation, remediation, threat, workflow, exposure,
  sla, ticketing/jira, defectdojo, scim/saml. (Some are import-coupled into
  `finding` via optional injection — disable at runtime, no schema change.)
- **Hard to remove: pentest.** Not `rm -rf pentest/` — it has ~12 hooks in
  non-pentest code:
  1. `findings.pentest_campaign_id` column + FK.
  2. `vulnerability.Finding.pentestCampaignID` + getters/setters.
  3. Constructor asset-optional exemption (`source != FindingSourcePentest`).
  4. `FindingSourcePentest` + 6 pentest-only `FindingStatus` values (the DB
     status CHECK was dropped in 000095 to allow them).
  5. `FindingRepository`: `pentest_campaign_id` columns + `IsPentestCampaignMember`
     + `source='pentest'` stats/filter branches.
  6. `FindingFilter` pentest fields + campaign-membership SQL subqueries.
  7. `VulnerabilityService.guardNotPentestManaged` / `assertPentestMember` on
     generic update/delete/bulk paths.
  8. `ctem_cycle_handler.go` `LEFT JOIN pentest_findings` (breaks if tables dropped).
  9. Attachment handler access-checker = `svc.Pentest`.
  10. `compliance_service.go` / `tenant_service.go` type-alias shims.
  11. `permission` (13 constants), `module` presets + hard `pentest→findings`
      dependency edge, `tenant.PentestSettings`, `jira` status mappings.
  12. Orphaned `finding_number` column (no Go readers).

## Plan: toward a modular monolith with feature flags

Goal: **turn a module off via config, and the system keeps running.** Phased,
each additive and independently shippable.

### Phase 1 — make the module system actually gate (low risk, high value) — **LARGELY SHIPPED**
A `RequireModule(moduleID)` middleware (`middleware.ModuleGate`) reads a tenant's
explicitly-disabled modules (via `ModuleService.TenantDisabledModules`), caches
them per-tenant (60s TTL), and **403s (`MODULE_NOT_ENABLED`) a disabled module's
route group**. It is **fail-open**: nil gate, missing tenant, core module, or any
lookup miss → allowed, so it can never block legitimate traffic. It is now wired
to **26 route groups** in `routes/routes.go` — including pentest, compliance,
attack-simulation, threat-intel, remediation, scan-pipelines, workflows,
attack-surface, exposures, suppressions, components, relationships, credentials,
scanner-templates, template-sources, IOCs, control-testing, reports, and the CTEM
groups (ctem-cycles, attacker-profiles, business-services, compensating-controls,
priority-rules, scope-config). Groups with no module-ID mapping (e.g. validation)
remain un-gateable. This turns the existing UI-only toggle into real per-tenant
enforcement **without touching any service logic or schema**. Core modules
(`module.IsCoreModule`) are never gateable. A module toggle now
**invalidates the gate cache immediately** (`ModuleService.notifyModuleChange`
→ `ModuleGate.Invalidate`), so enforcement is instant, not TTL-bounded.
Follow-up: wrap the remaining optional feature groups.

### Phase 2 — per-deployment optional construction (leaf features first)
Give `NewServices`/`NewRepositories` a seam to **skip** a module's construction
behind a config flag, starting with the clean bolt-ons (their handlers are
already nil-guarded, so nil-ing them omits routes). Establishes the pattern
without the pentest complexity.

### Phase 3 — invert the pentest core hooks (the hard, deliberate part)
Un-weave pentest from core so it becomes a real bolt-on:
- Source-agnostic `Finding` with pentest metadata behind an interface (drop the
  embedded `pentestCampaignID` field + special-case constructor).
- A **pentest-owned association table** instead of `findings.pentest_campaign_id`
  (removes the one core→feature FK).
- Register pentest **permissions dynamically** rather than baking 13 constants
  into the shared `permission` package.
- Make the attachment access-check a **pluggable checker**, not `svc.Pentest`.
- Rewrite `ctem_cycle_handler`'s `pentest_findings` JOIN behind the interface.

### Cross-cutting — enforce the layering with a lint — **DONE (domain layer)**
A **depguard** rule (`core-domain-isolation` in `.golangci.yml`) now forbids the
core domain packages (`asset`, `vulnerability`, `component`, `relationship`,
`findingsource`) from importing any feature domain or `internal/app` service —
freezing the healthy direction so new code can't re-entangle core with features.
Follow-up: extend to `internal/app/<core>` once its existing optional
feature-service imports (aitriage/validation, removed in Phase 3) are gone.

## Verdict

The system **does not die** without a feature at the wiring level — routes are
nil-guarded and services are optional. Per-tenant runtime **toggling** is now
solved: **Phase 1 (the `RequireModule` middleware) has shipped** across 26 route
groups. What remains is per-deployment optional *construction* by config
(**Phase 2**) and the gap between "disable" and "cleanly remove", which is real
only for **pentest** (**Phase 3**). Everything else is already close to a clean
bolt-on.
