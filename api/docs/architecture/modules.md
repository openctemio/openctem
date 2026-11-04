# Modules

A module is a feature an organization can have on or off: pentest,
compliance, EASM (`attack_surface`), automations (`workflows`), and so on.
Design and roadmap: [RFC-064](../rfcs/RFC-064-modules-entitlements-preferences.md).
Code: `configs/modules/<id>.yaml` (the registry: every module, its dependencies
and the routes, MCP tools and jobs it owns), `pkg/domain/module` (generated
catalog, presets, toggle rules), `internal/app/module` (state, toggles,
bundles), `internal/infra/http/middleware/module_gate.go` (gate).

## The registry

`configs/modules/` is the one declaration: one file per top-level module,
`configs/modules/<id>.yaml`, holding that module and its sub-modules
(`<id>.<name>`), so changes to different modules never touch the same file.
The generator merges them in a fixed order (top-level modules by `order`, then
id; each followed by its sub-modules by `order`, then id). The field reference
is in the `cmd/gen-modules` package comment. `make generate-modules`
(`go run ./cmd/gen-modules`) writes:

- `pkg/domain/module/registry_generated.go`: the `Module*` constants and
  `Registry`; `CoreModuleIDs`, `UserFacingModuleIDs`,
  `ModulePermissionMapping` and `ModuleDependencies` are derived from it;
- `web/src/config/modules.generated.ts`: the ids, core set and release status
  the console uses.

`make modules-sql` prints the block that writes the `modules` rows (insert or
update every declared module, retire any other row). A migration carries it;
`make modules-check` (CI: Module Registry Drift) fails when either generated
file or the newest migration block differs from the YAML.

Coverage tests read the registry:

- `TestEveryRouteFollowsTheModuleRegistry`: every route under a module's
  `routes` prefix is gated by `RequireModule` for that module, every
  `RequireModule` gate of a non-core module is declared, and every declared
  prefix matches a route. The gate is read from the route source, through
  gate parameters to the call site.
- `TestMCP_EveryToolAndPromptFollowsTheRegistry`: every MCP tool and prompt
  is listed under one module and carries that module.
- `TestEveryJobBelongsToAModule`: every controller the server builds is listed
  under one module.
- `TestEveryModuleJobSkipsADisabledTenant`: every job of a module that can be
  switched off names a test that proves it leaves a tenant with the module off
  alone.
- The web test `module-registry.test.ts`: every module id the console names
  (route map, sidebar, settings rail, embedded checks) exists.

## State cache and ETag

One `ModuleGate` per process (shared by the route gate, the dashboard and the threat-alert planner) keeps the effective state of an organization for at most 60 seconds. The entry:

- is dropped by every module toggle, preset, reset and entitlement change (one organization, or all of them after a plan mapping change), on every replica through the Redis bus; a read that started before the drop does not store its answer after it;
- ends at the next moment the state changes by itself: a read-only grace ending or a timed deny running out (`NotEntitledWithDeadline`);
- is never stored when a read failed (the entitlement could not be read, so every non-core module is reported `unavailable`, or the preferences could not be read): the answer is closed for that request and the next request reads again.

The ETag of `/me/modules`, `/settings/modules` and the event-type catalog is `ModuleService.ETagToken`: the Redis version counter, a hash of the effective state of every module and a fingerprint of the registry. A change with no write (grace end, entitlement reader recovering) changes the hash. A counter lost to a Redis flush or an eviction reads as 0, a value the counter never hands out, so an old ETag cannot match again.

## Rules

1. **A module gates a surface it owns, never an attribute of a core object.**
   Example: the SLA deadline is an attribute of every finding, so SLA is core.
2. **Off means off on every surface:** REST routes, MCP tools and prompts,
   background jobs, event-triggered automations and the console.
3. **The module gate is not authorization.** Permissions and data scope apply
   on top of it. A module never widens access.
4. **Core is honest.** A module that cannot be switched off is core and shows
   as "Always on".
5. **No switch without an effect.** A module that owns no surface is removed.

## State

```
on(org, module) = core(module)
               || (!platform_off(module) && entitled(org, module) && !explicit_off(org, module))

entitled(org, module) = !deny(org, module)   # a deny of any origin
explicit_off          = an org switch, counted only for a module Settings > Modules lists
```

The set is closed over hard dependencies: a module whose hard dependency (or
whose parent) is off is off too, with that module's reason
(`InheritOffFromHardDependencies`). A deny of compensating controls therefore
turns control testing off on every surface, and a dependent of a module in its
read-only grace is read-only until the same date.

- **Core** (`CoreModuleIDs`, and `modules.is_core`, which a parity test keeps
  equal): dashboard, assets, findings, scans, SLA, risk scoring, suppressions,
  team, roles, audit, settings, sensors, groups, API keys, notification
  settings, integrations. Risk scoring applies to every finding and an approved
  suppression rule always mutes what it matches, so neither can be switched off.
- **Platform scope** (`scope: platform` in the registry, never core): an
  installation switch, such as the vulnerability catalog (RFC-143). Its state
  comes from platform configuration (`PlatformModules`) and is folded into the
  state as the reason `disabled_by_platform` for every organization, before the
  plan and the organization's own switch, failing closed (a switch that cannot
  be read, or no provider wired, is off). The answer is `403 MODULE_NOT_ENABLED`
  with `reason: disabled_by_platform` ("This module is disabled by the
  platform"), not a 404. The organization cannot switch it on.
- **Retired and folded modules:** `risk_analysis`, `sbom_export`, `tools`,
  `scan_profiles` and the `integrations.*` sub-modules gated nothing and are
  gone. `business_impact`, `crown_jewels`, `ctem_maturity`, `executive_summary`
  and `mitre_coverage` hid a console page only: the page follows its parent
  (`business_services`, `assets`, `ctem_cycles`, `reports`, `threat_intel`).
  `ai_triage` is not on Settings > Modules: Settings > AI owns whether AI runs,
  with its consent dialog; the module stays as an entitlement only.
- **Explicit overrides:** `tenant_modules`, written by Settings > Modules
  (team admin with `settings:write`). Every change is audited as
  `tenant.modules_updated`.
- **Entitlements** (`internal/app/entitlement`, RFC-064,
  [limits.md](limits.md)): every module is available unless denied for one
  organization (`tenant_feature_denies`): by the operator in Console >
  Organizations > Modules (ops admin and up, with a reason, a fresh
  authenticator code and an optional expiry; lifting one needs a reason and a
  code too), or by a hosted service's control plane through the internal
  API. Changes are in the admin audit log and refresh the organization's
  module state at once. An organization cannot switch on a module it is not
  entitled to.
- **Presets** write overrides once (Settings > Modules, or the starting set
  picked at onboarding) and change nothing else. A preset changes only the
  modules Settings > Modules lists (`user_facing`): a module the page does not
  list keeps its state, so nothing a preset switches off is out of reach. A
  module the organization is not entitled to is left off and reported in the
  preview's `unavailable` list instead of failing the preset. The organization-chosen
  product bundles are retired.
- **Read-only grace** (`tenant_module_grace`): an organization that loses a
  module keeps reading it for 30 days (`limits.GracePeriod`). Grace starts
  when a deny (of any origin) takes the module away, and ends when the module
  comes back. During grace GET, HEAD and OPTIONS pass the gate; every other method
  gets `403 read_only_grace`, so creating a report or a POST search is
  refused too, while GET exports and downloads work. Jobs, MCP tools and
  automations treat the module as off at once. The module stays in the
  session's module list (pages render with a "Read-only until" banner) and in
  `read_only_modules`; it cannot be switched on. After grace the reason is
  `not_entitled`. Data is never deleted.
- **MCP:** a tool that only reads, and a prompt, work during the read-only
  grace (as the GET routes do); a tool that changes data needs the module on.
- **Failures:** a preference read error fails open (nothing disabled, the
  answer is not cached); an entitlement read error fails closed: every non-core module is
  `unavailable` and the gate answers 503 until it can be read again.

Each off module has a reason, returned in `MODULE_NOT_ENABLED` details:
`not_entitled`, `disabled_by_admin`, `disabled_by_platform`, `read_only_grace`
(writes only; 403) or `unavailable` (503). The console
says "Not available for this organization" (with no way to turn it on) or "Turned off for your
organization" (with Settings > Modules for an administrator).

## Where a module is enforced

| Surface | How |
|---|---|
| REST | `ModuleGate.RequireModule(id)` on the route group. Answers `403 MODULE_NOT_ENABLED`. Cached 60s per organization and dropped on every replica at once by the Redis bus `modules:changed`. |
| MCP | Each tool and prompt names the module of its REST route (`Module`), as the registry lists it. When that module is off, the tool is not listed and a call is refused. |
| Background jobs | `ModuleGuard` (`TenantDisabledModules`) in every job owned by a module that can be switched off (the registry `jobs` list): the EASM jobs, report scheduler, control-test scheduler, threat-model refresh, the remediation jobs (progress, task reconcile, query tasks, ticket push, suggestions), program sync, feed reconcile and assignment, the AI agent sweep, rule-source sync and the threat-alert planner. A job that must run whatever the tenant chose (retention, repairs that keep the scope boundary consistent, coverage and enrichment of core scanning) is owned by a core module. Sweeps that read the oldest N rows of all tenants leave a disabled tenant out of the query (`CollectEnabled`), so its rows cannot fill the batch and starve the others. |
| Automations | `WorkflowEventDispatcher` starts nothing for an organization with `workflows` off. |
| AI triage | Routes gated on `ai_triage`; auto-triage does not start when it is off. |
| Ingest | Suppression rules apply only with `suppressions` on. |
| Console | Sidebar, route guard (`route-permissions.ts`) and embedded panels (`useModuleEnabled`) read the module set from the session bootstrap. It is refreshed after a save and on `module.updated` in every tab. |

Deliberately not gated:

- Domain re-verification, which revokes stale proofs that gate scanning.
- The integration syncs: integrations is core.

## Adding a module

1. Add `configs/modules/<id>.yaml` (a sub-module goes in its parent's file) (id, const, presentation, read
   permission, dependencies with a reason), run `make generate-modules`, and
   add a migration whose body is `make modules-sql`.
2. Gate every surface it owns and list it in the registry: the route groups
   (`routes`), the MCP tools (`mcp`), the jobs (`jobs`); give its jobs and
   automation triggers a module guard. Gate the console route, the sidebar
   entry and every panel that other pages embed.
3. File its permissions under it (`permissions.module_id`).
   `TestModuleCatalog_EveryPermissionHasALiveModule` fails otherwise.
