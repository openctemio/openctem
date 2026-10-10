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
enabled(org, module) = core(module)
                    || !(explicit_off(org, module) || outside_bundles(org, module))
```

- **Core** (`CoreModuleIDs`, and `modules.is_core`, which a parity test keeps
  equal): dashboard, assets, findings, scans, SLA, team, roles, audit,
  settings, sensors, groups, API keys, notification settings, integrations,
  integrations.notifications.
- **Explicit overrides:** `tenant_modules`, written by Settings > Modules
  (team admin with `settings:write`). Every change is audited as
  `tenant.modules_updated`.
- **Bundles:** `tenants.settings.subscribed_bundles`. When set, every
  non-core module outside the bundles is off unless an override turns it on.
- **Presets** write overrides once and change nothing else.
- **Failures fail open:** a lookup error, or bundles that are all unknown,
  disables nothing.

Plans do not gate modules today; they set numeric limits
([plans-and-limits.md](plans-and-limits.md)). Entitlements per plan are
RFC-064 M3.

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
