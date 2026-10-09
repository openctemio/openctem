# Modules

A module is a feature an organization can have on or off: pentest,
compliance, EASM (`attack_surface`), automations (`workflows`), and so on.
Design and roadmap: [RFC-064](../rfcs/RFC-064-modules-entitlements-preferences.md).
Code: `configs/modules.yaml` (the registry: every module, its dependencies
and the routes, MCP tools and jobs it owns), `pkg/domain/module` (generated
catalog, presets, toggle rules), `internal/app/module` (state, toggles,
bundles), `internal/infra/http/middleware/module_gate.go` (gate).

## The registry

`configs/modules.yaml` is the one declaration. `make generate-modules`
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
- The web test `module-registry.test.ts`: every module id the console names
  (route map, sidebar, settings rail, embedded checks) exists.

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
               || (entitled(org, module) && !explicit_off(org, module))

entitled(org, module) = !deny(org, module)
                     && (plan_includes(plan(org), module) || grant(org, module))
```

- **Core** (`CoreModuleIDs`, and `modules.is_core`, which a parity test keeps
  equal): dashboard, assets, findings, scans, SLA, team, roles, audit,
  settings, sensors, groups, API keys, notification settings, integrations,
  integrations.notifications.
- **Explicit overrides:** `tenant_modules`, written by Settings > Modules
  (team admin with `settings:write`). Every change is audited as
  `tenant.modules_updated`.
- **Entitlements** (`internal/app/entitlement`, RFC-064): the plan to module
  map (`platform_settings['plan_modules']`, every module for every plan until
  a super admin narrows it in Console > System > Plans) and the grants and
  denies of one organization (`tenant_module_grants`, Console >
  Organizations > Plan, ops admin and up, with a reason and an optional
  expiry). Changes are in the admin audit log and refresh the organization's
  module state at once (a plan mapping change refreshes every organization).
  An organization cannot switch on a module it is not entitled to.
- **Presets** write overrides once (Settings > Modules, or the starting set
  picked at onboarding) and change nothing else. The organization-chosen
  product bundles are retired: packaging is the plan's.
- **Read-only grace** (`tenant_module_grace`): an organization that loses a
  module keeps reading it for 30 days (`plan.GracePeriod`). Grace starts when
  a deny, the removal of a grant, a change of the organization's plan or a
  plan mapping change takes the module away, and ends when the module comes
  back. An expired trial grant gives the same grace from its expiry, with no
  row. During grace GET, HEAD and OPTIONS pass the gate; every other method
  gets `403 read_only_grace`, so creating a report or a POST search is
  refused too, while GET exports and downloads work. Jobs, MCP tools and
  automations treat the module as off at once. The module stays in the
  session's module list (pages render with a "Read-only until" banner) and in
  `read_only_modules`; it cannot be switched on. After grace the reason is
  `not_entitled`. Data is never deleted.
- **Failures:** a preference read error fails open (nothing disabled); an
  entitlement read error fails closed: every non-core module is
  `unavailable` and the gate answers 503 until it can be read again.

Each off module has a reason, returned in `MODULE_NOT_ENABLED` details:
`not_entitled`, `disabled_by_admin`, `read_only_grace` (writes only; 403) or
`unavailable` (503). The console
says "Not in your plan" (with no way to turn it on) or "Turned off for your
organization" (with Settings > Modules for an administrator).

## Where a module is enforced

| Surface | How |
|---|---|
| REST | `ModuleGate.RequireModule(id)` on the route group. Answers `403 MODULE_NOT_ENABLED`. Cached 60s per organization and dropped on every replica at once by the Redis bus `modules:changed`. |
| MCP | Each tool and prompt names the module of its REST route (`Module`), as the registry lists it. When that module is off, the tool is not listed and a call is refused. |
| Background jobs | `ModuleGuard` (`TenantDisabledModules`) in the report scheduler, certificate monitor, EASM DNS checks, graph enrichment, scope join re-evaluation, threat-model refresh, control-test scheduler and remediation progress. |
| Automations | `WorkflowEventDispatcher` starts nothing for an organization with `workflows` off. |
| AI triage | Routes gated on `ai_triage`; auto-triage does not start when it is off. |
| Ingest | Suppression rules apply only with `suppressions` on. |
| Console | Sidebar, route guard (`route-permissions.ts`) and embedded panels (`useModuleEnabled`) read the module set from the session bootstrap. It is refreshed after a save and on `module.updated` in every tab. |

Deliberately not gated:

- Domain re-verification, which revokes stale proofs that gate scanning.
- The integration syncs: integrations is core.

## Adding a module

1. Add it to `configs/modules.yaml` (id, const, presentation, read
   permission, dependencies with a reason), run `make generate-modules`, and
   add a migration whose body is `make modules-sql`.
2. Gate every surface it owns and list it in the registry: the route groups
   (`routes`), the MCP tools (`mcp`), the jobs (`jobs`); give its jobs and
   automation triggers a module guard. Gate the console route, the sidebar
   entry and every panel that other pages embed.
3. File its permissions under it (`permissions.module_id`).
   `TestModuleCatalog_EveryPermissionHasALiveModule` fails otherwise.
