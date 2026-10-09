# RFC-064: Modules — entitlements, preferences and one registry

| | |
|---|---|
| Status | Accepted (decisions MD1–MD12 delegated to the platform team, 2026-10-09) |
| Authors | Platform team |
| Related | Plans and limits ([architecture](../architecture/plans-and-limits.md)), RFC-022 (platform admin console), RFC-062 (MCP authorization), module system ([architecture](../architecture/modules.md)) |
| Code | #1583 (SLA core), #1590 (every surface and replica), #1594 (catalog cleanup, permissions), #1596 (console consistency); M1–M5 below |

## 1. Summary

A module is a feature an organization can have or not have, such as pentest,
compliance or EASM. Today one switch per module (`tenant_modules`) does three
different jobs:

- **packaging**: what the organization paid for;
- **release**: whether the feature is ready, through beta and coming soon;
- **simplification**: what the team does not want to see.

It enforced none of them consistently. A module gated a few REST route
groups. Ingest, background jobs, notifications, MCP tools, dashboards and
other modules' pages ignored it. The visible symptom: SLA badges on every
finding while `/assets/{id}/sla-policy` answered `MODULE_NOT_ENABLED`.

This RFC separates the three jobs and gives each an owner and an enforcement
rule:

| | Entitlement | Preference | Release |
|---|---|---|---|
| Question | May this organization use it? | Does this organization want it? | Is it ready? |
| Set by | Platform (plan, grant, licence) | Organization owner or admin | Engineering (registry) |
| Storage | `platform_settings['plan_modules']`, `tenant_module_grants` | `tenant_modules` (exists) | registry `release` |
| Lookup failure | Deny with 503, never grant | Allow (cosmetic) | n/a |
| Audit | Platform audit, step-up | Organization audit (exists) | git |

```
effective(org) = core ∪ close_over_hard_deps(entitled ∩ preferred ∩ released)
```

One function computes it, with one cache, and every surface reads it.

## 2. Rules

- **R1. A module gates a surface it owns, never an attribute of a core
  object.** SLA deadlines, priority class, threat-intel enrichment and
  suppression of findings are attributes of findings: their effect is core,
  or the module switches off the effect everywhere (ingest included). SLA is
  core (#1583).
- **R2. Off means off on every surface.** That covers REST, MCP tools and
  prompts, background jobs, event-triggered automations, notifications,
  exports and report sections, dashboards, search and the console (navigation,
  route, embedded panels). The registry lists a module's surfaces, and a test
  fails on an unclassified route, job or tool.
- **R3. The module gate is not authorization.** Permissions and data scope
  still apply on top. A module never widens access.
- **R4. Core is honest.** A module the organization cannot switch off is core
  and shows as "Always on". There is no third "mandatory" tier.
- **R5. No switch without an effect.** A module must own at least one
  surface; otherwise it is removed (#1594).

## 3. Threat model

| Threat | Control |
|---|---|
| A Free organization uses a paid module through the API, MCP or a background job | Entitlement is checked at the same seam as preference, on every surface (R2); entitlement lookups fail closed |
| An organization admin grants itself a paid bundle | Bundles become platform-side entitlements; the organization endpoint keeps only presets of preferences (MD6) |
| A stale replica serves a module after it was revoked | The module change bus drops the cache on every replica (#1590); entitlement entries also carry a version |
| One organization's cache entry is served to another | Cache keyed by organization id; a cross-organization test covers the gate, MCP and jobs |
| Entitlement changes without trace | Platform audit record with administrator, reason and expiry; step-up for grant, revoke and plan mapping |
| The `MODULE_NOT_ENABLED` error leaks data | It names the module and the reason only; module ids are public product facts |
| Client-only gating | The console reflects the API decision; every check is repeated server side |

## 4. Design

### 4.1 Registry (M2)

`api/configs/modules.yaml` is the single declaration, as `asset-types.yaml`
is for asset types:

```yaml
- id: pentest
  name: Penetration testing
  stage: validation
  release: released          # released | beta | coming_soon | deprecated
  core: false
  depends: [{id: findings, kind: hard}]
  permission: pentest:campaigns:read
  plans: [pro, enterprise]   # default entitlement
  surfaces:
    routes: [/api/v1/pentest/]
    mcp: [get_campaign, list_campaign_findings, exec_summary]
    jobs: []
    events: []
    web: [/pentest/**, /validation/retests]
```

The registry generates:

- the Go catalog (constants, core set, permission mapping, dependency graph);
- the `modules` rows, upserted at startup and removed when retired, with no
  migration per module;
- the web `Module` constants and route-module map.

Tests require that:

- every `/api/v1` route group is core or belongs to exactly one module;
- every controller and every MCP tool names a module or `core`;
- the web route map is a subset of the registry.

### 4.2 Entitlements (M3)

- **Plan mapping.** `platform_settings['plan_modules']` holds
  `{free: [...], pro: [...], enterprise: ["*"]}`, defaulting from the registry
  `plans`. An organization without a plan row is Enterprise, as for limits, so
  self-hosted deployments are entitled to everything.
- **Grants.** `tenant_module_grants(tenant_id, module_id, kind, expires_at,
  reason, set_by, set_at)`, where `kind` is `grant` or `deny`. A grant covers
  trials and add-ons beyond the plan. A deny covers regional or compliance
  restrictions.
- **Entitled set.** plan modules ∪ active grants − active denies.
- **Fail closed.** The entitlement lookup never answers "entitled" on error.
  A cached value is used for up to 5 minutes; past that, the request gets 503.

### 4.3 Preferences

`tenant_modules` keeps today's meaning, restricted to entitled modules.
Presets (EASM, VM, ASPM, CTEM full) write preferences once. Applying a preset
never changes entitlements.

### 4.4 Disable and downgrade semantics (M4)

| Event | Reads | Writes | Jobs and automations | Schedules | Data |
|---|---|---|---|---|---|
| Preference off | 403 `disabled_by_admin` | 403 | skipped | paused (unchanged) | kept |
| Entitlement lost | allowed 30 days (`read_only_grace`) | 403 | stopped at once | paused | kept; export allowed |
| Grace ended | 403 `not_entitled` | 403 | stopped | paused | kept until the organization is deleted or purged |
| Turned on again | yes | yes | resume on the next tick; no catch-up burst | resume | derived data recomputed by the existing refresh jobs |

### 4.5 Error and console

```json
{"code":"MODULE_NOT_ENABLED","message":"...","details":{"module":"pentest","reason":"not_entitled"}}
```

The `reason` is one of `not_entitled`, `disabled_by_admin`,
`read_only_grace` or `beta_not_enabled`.

The console shows one state for a module that is off, used by the route
guard and by every embedded panel:

- not entitled: "Available on Pro", with contact (or upgrade, once billing
  exists);
- switched off: "Turned off for your organization", with **Manage modules**
  for administrators (#1596);
- an embedded panel hides silently.

### 4.6 API contract

Platform console (`/api/v1/admin`, platform administrators):

- `GET /admin/settings/plan-modules` and `PUT /admin/settings/plan-modules`
  (step-up): the plan to module mapping.
- `GET /admin/tenants/{id}/modules`: for each module, `entitled`,
  `entitlement_source` (`core | plan | grant | deny`), `grant_expires_at`,
  `preferred`, `effective` and `reason`.
- `PUT /admin/tenants/{id}/modules/{module}/grant`, body
  `{"kind":"grant"|"deny","expires_at"?,"reason"}`, step-up and audited.
- `DELETE /admin/tenants/{id}/modules/{module}/grant` (step-up, audited):
  removes the grant; losing an entitlement starts the read-only grace.

Organization:

- `GET /tenants/{t}/settings/modules` gains `entitled` and
  `entitlement_source` per module. A module that is not entitled shows locked.
- `POST /tenants/{t}/settings/modules/bundles` is removed. Bundles become
  platform-side packaging; presets remain for preferences.

## 5. Use cases covered

- Free, Pro and Enterprise packaging.
- 14-day trial of one module.
- Paid add-on.
- On-premise customer with everything entitled.
- An administrator hides modules the team does not use.
- Persona presets at onboarding.
- Beta access for chosen organizations.
- Deprecation: read-only, then removal.
- Regional restriction (deny).
- Downgrade with read-only grace and export.
- Turning a module back on.
- API-only and MCP-only customers seeing the same set as the console.
- Report and export sections omitted for an off module.
- Support seeing why a module is off (`reason` in the admin view).

Out of scope: a parent organization managing modules for child
organizations (no organization hierarchy exists). Entitlements are per
organization, so this can be layered on later.

## 6. Decisions

| Id | Decision |
|---|---|
| MD1 | Three concepts (entitlement, preference, release), one effective set, one seam |
| MD2 | R1: modules never switch off attributes of core objects; SLA is core |
| MD3 | R2: every surface classified by the registry, enforced by tests |
| MD4 | Entitlements fail closed (503); preferences fail open |
| MD5 | No plan row means Enterprise: self-hosted is entitled to everything |
| MD6 | Bundles are platform-side packaging; organization admins apply presets only |
| MD7 | 30-day read-only grace after an entitlement is lost; jobs stop at once |
| MD8 | Mandatory tier removed; always-on modules are core (#1594) |
| MD9 | Module changes reach every replica through Redis at once (#1590) |
| MD10 | `MODULE_NOT_ENABLED` stays 403 and gains `details.reason`; no 404 masking (module ids are public) |
| MD11 | The registry upserts catalog rows at startup; migrations only move data |
| MD12 | Entitlement changes need step-up and are recorded in the platform audit |

## 7. Plan

| Step | Content | Status |
|---|---|---|
| M0 | SLA core; every surface (MCP, AI triage, automations, remediation progress); cross-replica invalidation; console refresh; catalog cleanup; permissions under live modules; console consistency | #1583, #1590, #1594, #1596 |
| M1 | `details.reason` on `MODULE_NOT_ENABLED`; one `ModuleUnavailable` console state | next |
| M2 | Registry, generators and coverage tests | after M1 |
| M3 | Entitlements: plan mapping, grants, admin console pages, organization view | after M2 |
| M4 | Downgrade grace, schedule pause and resume | after M3 |
| M5 | Bundles move to the platform; the organization bundle endpoint is removed | with M3 |
