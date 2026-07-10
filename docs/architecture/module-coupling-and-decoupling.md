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
- The **`Module`/`TenantModule` system is UI metadata only** — it drives the
  sidebar and a notification-event filter; **no middleware gates any route**.
  Disabling a module in `tenant_modules` hides it from the sidebar but every
  endpoint stays live.
- So today a module can be **disabled at the route layer only by leaving its
  handler nil** (deployment-wide, all-or-nothing), not per-tenant at runtime and
  not by config.
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
| **Runtime (module gating)** | None. `tenant_modules.is_enabled` read only by the bootstrap/sidebar handler + a notification filter. No `RequireModule` middleware exists. | `bootstrap_handler.go:243`, `migrations/000004` (`'Feature registry for UI navigation'`) |

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

### Phase 1 — make the module system actually gate (low risk, high value) — **STARTED**
A `RequireModule(moduleID)` middleware (`middleware.ModuleGate`) reads a tenant's
explicitly-disabled modules (via `ModuleService.TenantDisabledModules`), caches
them per-tenant (60s TTL), and **403s a disabled module's route group**. It is
**fail-open**: nil gate, missing tenant, core module, or any lookup miss →
allowed, so it can never block legitimate traffic. Wired to the **pentest** and
**compliance** groups first (appended after tenant extraction); remaining
optional feature groups get wrapped incrementally the same way. Turns the
existing UI-only toggle into real per-tenant enforcement **without touching any
service logic or schema**. Core modules (`CoreModuleIDs`) are never gateable.
Follow-up: explicit cache invalidation on toggle (currently TTL-bounded).

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

### Cross-cutting — enforce the layering with a lint
Add a **depguard** rule (CI): `pkg/domain/<core>` and `internal/app/<core>` must
**not** import feature packages. This freezes the healthy direction so new code
can't re-entangle core with features.

## Verdict

The system **does not die** without a feature at the wiring level — routes are
nil-guarded and services are optional. The gap between "nil the handler at deploy"
and "toggle per-tenant via config" is **Phase 1** (a middleware). The gap between
"disable" and "cleanly remove" is real only for **pentest** (Phase 3). Everything
else is already close to a clean bolt-on.
