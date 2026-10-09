# Modules

A module is a feature an organization can have on or off: pentest,
compliance, EASM (`attack_surface`), automations (`workflows`), and so on.
Design and roadmap: [RFC-064](../rfcs/RFC-064-modules-entitlements-preferences.md).
Code: `pkg/domain/module` (catalog, core set, presets, dependency graph),
`internal/app/module` (state, toggles, bundles),
`internal/infra/http/middleware/module_gate.go` (gate).

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
| MCP | Each tool and prompt names the module of its REST route (`Module`). When that module is off, the tool is not listed and a call is refused. `TestMCP_EveryToolAndPromptIsClassified` fails on an unclassified tool. |
| Background jobs | `ModuleGuard` (`TenantDisabledModules`) in the report scheduler, certificate monitor, EASM DNS checks, graph enrichment, threat-model refresh, control-test scheduler and remediation progress. |
| Automations | `WorkflowEventDispatcher` starts nothing for an organization with `workflows` off. |
| AI triage | Routes gated on `ai_triage`; auto-triage does not start when it is off. |
| Ingest | Suppression rules apply only with `suppressions` on. |
| Console | Sidebar, route guard (`route-permissions.ts`) and embedded panels (`useModuleEnabled`) read the module set from the session bootstrap. It is refreshed after a save and on `module.updated` in every tab. |

Deliberately not gated:

- Domain re-verification, which revokes stale proofs that gate scanning.
- The integration syncs: integrations is core.

## Adding a module

1. Add the constant and its read permission in `pkg/domain/module/module.go`.
   If it depends on another module, add the edge in `dependency.go`.
2. Seed the `modules` row in a migration. The catalog parity tests fail
   otherwise.
3. Gate every surface it owns: the route group, the MCP tools, the jobs and
   the automation triggers. Gate the console route, the sidebar entry and
   every panel that other pages embed.
4. File its permissions under it (`permissions.module_id`).
   `TestModuleCatalog_EveryPermissionHasALiveModule` fails otherwise.
