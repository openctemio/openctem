---
name: api-route
description: Checklist for adding or changing an API route, permission or module gate in api/ - least-privilege gate, route coverage and data-scope registries, permission catalog sync, module gating, tenant isolation, regenerated contract, negative tests. Use whenever a handler, route, permission or module boundary changes.
---

The canonical model is `api/docs/architecture/authorization-matrix.md`; read it before touching a gate.

1. **Gate the route** with the least-privilege `middleware.Require(permission.X)` (or `RequireTeamAdmin/Owner`
   for `/tenants/{tenant}/*`). Use the precise action permission (`findings:status`, not `findings:write`).
   A truly public or self route goes into `allowlistPrefixes` in `api/tests/unit/route_authz_coverage_test.go`
   with a reason.
2. **Classify its data scope** in `dataSurfaceRegistry` (`api/tests/unit/route_scope_classification_test.go`):
   scoped, partial, gap (with its research id), separate, config or system. CI fails on an unclassified route.
3. **New permission:** add it in all three places together: `permission.go` (`AllPermissions()`), a seed
   migration (additive, with a working `.down.sql`, see the `migration` skill) and the web constants in
   `web/src/lib/permissions/constants.ts`. `permission_catalog_sync_test.go` fails when Go and DB disagree.
   Grant it to roles through the seed, never by widening another route's gate.
4. **Module:** a route that belongs to a module is mounted with `h.ModuleGate.RequireModule(moduledom.X)` in
   `routes.go` and its module is declared in the module catalog (`api/pkg/domain/module`; the single registry
   design is RFC-064). Jobs, MCP tools, notifications and exports of that module honour the same toggle.
   The module gate is a product gate, not a security boundary: the permission gate still applies.
5. **Tenant isolation:** the tenant comes from the authenticated context (sensors: from the sensor key), never
   from the body, query or an uploaded report. Every query on a tenant table, including updates and deletes,
   carries `AND tenant_id = $n`. Integrations resolve per-tenant credentials, never a shared client.
6. **Data scope:** a member with no scope row sees nothing. Never add a fail-open mode.
7. **Regenerate the contract:** `make generate` at the repo root (`make generate-docker` without Go or Node).
   The OpenAPI spec, web API types and route permission map are generated, not committed.
8. **Tests:** handler and service tests, plus a cross-tenant negative (tenant B gets 404 on tenant A's object)
   and an out-of-scope negative (member without the permission or scope is refused). Integration tests run
   against a scratch Postgres.
9. **Web:** hide or disable the action with `<Can permission={...}>`, but the backend stays the only authority.
   A 403 response names the missing permission; surface it.
10. Update the architecture doc for the feature and add a changelog fragment (`pr-checklist` skill).
