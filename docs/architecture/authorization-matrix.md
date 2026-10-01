# Authorization Matrix

This document describes the complete authorization model for the OpenCTEM API.

## Overview

The system uses a **two-layer authorization model**:

1. **Permission-based Authorization**: Fine-grained permissions (`resource:action`) embedded in JWT tokens
2. **Role-based Authorization**: Team roles (owner, admin, member, viewer) for team management

## Authorization Models

### Permission-based (JWT Claims)

Permissions are included in the access token and checked using `middleware.Require()`.

**The canonical permission list is code, not this document.** The single source
of truth is `permission.AllPermissions()` in
`pkg/domain/permission/permission.go`; `permission.IsValid()` /
`ParsePermission()` validate against it. As of this writing it defines
**164 permissions**, grouped by module. Rather than hand-mirror all 164 (which
would drift), the table below lists the module groups and the count each
contributes — derive the exact strings from `AllPermissions()`.

| Module group | Count | Example permissions |
|--------------|-------|---------------------|
| Core (dashboard, audit, settings) | 4 | `dashboard:read`, `audit:read`, `settings:read/write` |
| Assets | 11 | `assets:read/write/delete/import/export`, `asset_groups:*`, `components:*` |
| Findings | 31 | `findings:read/write/delete/assign/triage/status/export/approve/fix_apply/verify`, `exposures:*`, `suppressions:*`, `vulnerabilities:*`, `credentials:*`, `remediation:*`, `workflows:*`, `policies:*` |
| Scans | 22 | `scans:read/write/delete/execute`, `scan_profiles:*`, `sources:*`, `tools:*`, `tenant_tools:*`, `scanner_templates:*`, `secret_store:*` |
| Agents | 6 | `agents:read/write/delete`, `commands:read/write/delete` |
| Team | 23 | `team:*`, `members:*`, `groups:*`, `roles:*`, `permission_sets:*`, `assignment_rules:*` |
| Integrations | 18 | `integrations:read/manage`, `scm_connections:*`, `notifications:*`, `webhooks:*`, `api_keys:*`, `pipelines:*` |
| Settings (billing, SLA) | 6 | `billing:read/write/manage`, `sla:read/write/delete` |
| Attack Surface | 3 | `scope:read/write/delete` |
| Validation (legacy) | 4 | `validation:read/write`, `pentest:read/write` |
| Pentest (granular) | 11 | `pentest_campaigns:*`, `pentest_findings:*`, `pentest_retests:*`, `pentest_templates:*`, `pentest_reports:write` |
| Compliance | 7 | `compliance_frameworks:*`, `compliance_assessments:*`, `compliance_mappings:*`, `compliance_reports:read` |
| Reports | 2 | `reports:read/write` |
| Threat Intel | 2 | `threat_intel:read/write` |
| AI Triage | 2 | `ai_triage:read/trigger` |
| CTEM (RFC-004/005) | 12 | `ctem_cycles:*`, `attacker_profiles:*`, `business_services:*`, `compensating_controls:*`, `priority_rules:*`, `verification_checklists:*` |
| **Total** | **164** | |

> There is **no `projects` module**. OpenCTEM has no `projects:*` permissions and
> no `/api/v1/projects/*` routes; the resource hierarchy is
> tenant → assets/components/findings. (This doc previously listed a phantom
> projects module — removed.)

### Role-based (Team Context)

Team roles are used for team management operations:

| Role | Level | Description |
|------|-------|-------------|
| `owner` | 4 | Team owner - full control, can delete team |
| `admin` | 3 | Team admin - manage members, invitations, settings |
| `member` | 2 | Team member - create/edit resources |
| `viewer` | 1 | Team viewer - read-only access |

## Middleware Stack

The authorization is implemented through a middleware chain:

```
Request
   │
   ▼
┌─────────────────────────────────────────┐
│ UnifiedAuth                              │ ← Validates JWT (local or OIDC)
│ - Extracts user ID, email, tenant ID     │
│ - Extracts permissions array             │
│ - Extracts role from claims              │
└─────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────┐
│ UserSync                                 │ ← Syncs user to local DB
└─────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────┐
│ RequireTenant (for JWT-tenant routes)    │ ← Validates tenant ID in token
│   OR                                     │
│ TenantContext (for URL-tenant routes)    │ ← Extracts tenant from path
└─────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────┐
│ RequireMembership (URL routes only)      │ ← Verifies team membership
└─────────────────────────────────────────┘
   │
   ▼
┌─────────────────────────────────────────┐
│ Require(permission) / RequireTeamAdmin   │ ← Permission or role check
└─────────────────────────────────────────┘
   │
   ▼
Handler
```

## API Routes by Authorization Type

### Public Routes (No Auth)

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /ready` | Readiness check |
| `POST /api/v1/auth/register` | User registration (403 unless `AUTH_ALLOW_REGISTRATION=true` or a matching invitation token) |
| `POST /api/v1/auth/login` | User login |
| `POST /api/v1/auth/token` | Token exchange |
| `POST /api/v1/auth/refresh` | Token refresh |

### JWT-Tenant Routes (Tenant from Token)

These routes use the tenant ID embedded in the JWT access token.

#### Assets (`/api/v1/assets`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/assets` | `assets:read` |
| `GET /api/v1/assets/{id}` | `assets:read` |
| `POST /api/v1/assets` | `assets:write` |
| `PUT /api/v1/assets/{id}` | `assets:write` |
| `DELETE /api/v1/assets/{id}` | `assets:delete` |

#### Components (`/api/v1/components`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/components` | `components:read` |
| `GET /api/v1/components/{id}` | `components:read` |
| `POST /api/v1/components` | `components:write` |
| `PUT /api/v1/components/{id}` | `components:write` |
| `DELETE /api/v1/components/{id}` | `components:delete` |

#### Findings (`/api/v1/findings`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/findings` | `findings:read` |
| `GET /api/v1/findings/{id}` | `findings:read` |
| `POST /api/v1/findings` | `findings:write` |
| `DELETE /api/v1/findings/{id}` | `findings:delete` |
| `PATCH /api/v1/findings/{id}/status` | `findings:status` |
| `POST /api/v1/findings/{id}/triage` | `findings:triage` |
| `POST /api/v1/findings/{id}/assign` · `/unassign` · `/actions/assign-to-owners` | `findings:assign` |
| `POST /api/v1/findings/bulk/status` · `/bulk/assign` | `findings:bulk_update` |
| `POST /api/v1/findings/{id}/verify` | `findings:verify` |

> The finding **action** routes (status, triage, assign, bulk, verify) are gated on
> **precise granular permissions**, not the coarse `findings:write` (AUTHZ-05).
> `verify` is a separate permission from `status`/`triage` to keep
> **separation of duties** — the person who triages a finding should not be able to
> self-verify their own fix (AUTHZ B1, api#505). Migration `000217` backfilled the
> four granular perms onto every role that already held `findings:write`, so the
> tightening is honest-not-breaking: nobody lost an action they could perform before.

#### Scan zones (`/api/v1/scan-zones`, RFC-023)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/scan-zones` · `/{id}` · `/coverage` | `sensors:zones:read` |
| `POST /api/v1/scan-zones` | `sensors:zones:write` |
| `PATCH /api/v1/scan-zones/{id}` | `sensors:zones:write` |
| `PUT` · `DELETE /api/v1/scan-zones/{id}/sensors/{sensorId}` | `sensors:zones:write` |
| `DELETE /api/v1/scan-zones/{id}` | `sensors:zones:delete` |

> Seeded by migration `000231`: owner and admin hold all three, member and
> viewer hold `sensors:zones:read` (RFC-023 D16). Object level: every query
> carries `tenant_id`, and `scan_zone_sensors` has composite foreign keys
> `(tenant_id, zone_id)` and `(tenant_id, sensor_id)`, so a zone or sensor of
> another tenant cannot be linked even by a wrong handler. See
> [scan-zones.md](scan-zones.md).

#### Vulnerabilities (`/api/v1/vulnerabilities`) - Global

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/vulnerabilities` | `vulnerabilities:read` |
| `GET /api/v1/vulnerabilities/{id}` | `vulnerabilities:read` |
| `GET /api/v1/vulnerabilities/cve/{cve_id}` | `vulnerabilities:read` |
| `POST /api/v1/vulnerabilities` | `vulnerabilities:write` |
| `PUT /api/v1/vulnerabilities/{id}` | `vulnerabilities:write` |
| `DELETE /api/v1/vulnerabilities/{id}` | `vulnerabilities:delete` |

#### Dashboard (`/api/v1/dashboard`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/dashboard/stats` | `dashboard:read` |
| `GET /api/v1/dashboard/stats/global` | `dashboard:read` |

### URL-Tenant Routes (Tenant from URL)

These routes require the tenant ID in the URL path and use database-based membership verification.

#### Teams (`/api/v1/tenants`)

| Endpoint | Required Role |
|----------|---------------|
| `GET /api/v1/tenants` | Any authenticated |
| `POST /api/v1/tenants` | Any authenticated |
| `GET /api/v1/tenants/{tenant}` | Any authenticated |

#### Team Management (`/api/v1/tenants/{tenant}`)

| Endpoint | Required Role |
|----------|---------------|
| `GET /api/v1/tenants/{tenant}/members` | Team viewer+ |
| `GET /api/v1/tenants/{tenant}/invitations` | Team viewer+ |
| `PATCH /api/v1/tenants/{tenant}` | Team admin+ |
| `POST /api/v1/tenants/{tenant}/members` | Team admin+ |
| `PATCH /api/v1/tenants/{tenant}/members/{id}` | Team admin+ |
| `DELETE /api/v1/tenants/{tenant}/members/{id}` | Team admin+ |
| `POST /api/v1/tenants/{tenant}/invitations` | Team admin+ |
| `DELETE /api/v1/tenants/{tenant}/invitations/{id}` | Team admin+ |
| `POST /api/v1/tenants/{tenant}/users` | Team admin+ (creates an account + one-time set-password link; RFC-025) |
| `POST /api/v1/tenants/{tenant}/users/{userId}/setup-link` | Team admin+ (only an unused account that belongs to this organization only) |
| `PATCH /api/v1/tenants/{tenant}/settings/security` | **Team owner only** (refuses an IP allowlist that excludes the caller's IP) |
| `DELETE /api/v1/tenants/{tenant}` | **Team owner only** |

> **Granting roles** (invitations and created users) is anti-escalation checked:
> a caller who is not an organization admin may grant only roles whose
> permissions they hold, and the owner role is never grantable. The membership
> role is derived from the granted RBAC roles (`member` if they include the
> system member/admin role, else `viewer`) and the granted roles become the
> user's exact role set, so the `tenant_members` → `user_roles` trigger cannot
> add more.

#### Invitations (`/api/v1/invitations`)

| Endpoint | Required Role |
|----------|---------------|
| `GET /api/v1/invitations/{token}` | Any authenticated |
| `POST /api/v1/invitations/{token}/accept` | Any authenticated (email must match) |

### User Routes (`/api/v1/users`)

| Endpoint | Required Auth |
|----------|---------------|
| `GET /api/v1/users/me` | JWT |
| `PUT /api/v1/users/me` | JWT |
| `PUT /api/v1/users/me/preferences` | JWT |
| `GET /api/v1/users/me/tenants` | JWT |
| `POST /api/v1/users/me/change-password` | JWT (local auth only) |
| `GET /api/v1/users/me/sessions` | JWT (local auth only) |
| `DELETE /api/v1/users/me/sessions` | JWT (local auth only) |
| `DELETE /api/v1/users/me/sessions/{id}` | JWT (local auth only) |

### Platform Admin Routes (`/api/v1/admin/*`)

Platform admin routes are for OpenCTEM operators, NOT tenant users. They
authenticate **only** with a **console session** (RFC-022: `/login` password
sign-in + mandatory TOTP, server-side session in the `admin_session` cookie,
scoped to `/api/v1/admin`; cookie-authenticated writes must pass the
`admin_csrf` double-submit check). There are **no admin API keys**: an
`X-Admin-API-Key` or `Authorization: Bearer` header authenticates nothing here,
so every admin action has passed TOTP. The session resolves to an
`admin_users` row with a platform role: `super_admin` > `ops_admin` >
`readonly`. The tenant JWT never authenticates these routes, and the admin
session never reaches tenant routes.

Authorization is enforced at the **route layer** in
`internal/infra/http/routes/admin.go` via `AdminAuthMiddleware.RequireRole(...)`
— not in the handlers.

| Endpoint | Required Role |
|----------|---------------|
| `GET /api/v1/admin/auth/validate` | any admin |
| `POST /api/v1/admin/auth/session`, `/mfa` | public (rate-limited; needs the `/login` refresh cookie, then TOTP) |
| `POST /api/v1/admin/auth/logout` | public (ends the caller's own console and `/login` session) |
| `POST /api/v1/admin/auth/password` | any admin (the only write allowed while `password_change_required`) |
| `GET /api/v1/admin/auth/idp` | public (enabled + display name of the platform IdP, nothing else) |
| `POST /api/v1/admin/auth/idp/start`, `/idp/callback` | public (token-exchange rate limit, 20/min; state bound to the `admin_idp` cookie, single use) |
| `POST /api/v1/admin/administrators` | **super_admin** (audited; `break_glass` audited high) |
| `POST /api/v1/admin/users/{id}/reset-credentials` | **super_admin** (audited; not self) |
| `POST /api/v1/admin/users/{id}/break-glass-test` | **super_admin** (audited; not the break-glass account itself) |
| `DELETE /api/v1/admin/users/{id}/idp-binding` | **super_admin** (audited high) |
| `GET/PUT/DELETE /api/v1/admin/platform-idp` | **super_admin** (writes audited high; secret never returned) |
| `GET /api/v1/admin/users` | **super_admin** |
| `GET /api/v1/admin/users/{id}` | **super_admin** |
| `PATCH /api/v1/admin/users/{id}` | **super_admin** (audited) |
| `DELETE /api/v1/admin/users/{id}` | **super_admin** (audited) |
| `GET /api/v1/admin/audit-logs` (+ `/stats`, `/{id}`) | any admin (readonly ok) |
| `GET /api/v1/admin/target-mappings` (+ `/stats`, `/{id}`) | any admin |
| `POST/PATCH/DELETE /api/v1/admin/target-mappings` | **ops_admin+** (rate-limited, audited) |

> The admin roster (`/admin/users`) is super_admin-only for reads as well as
> writes: it exposes admin emails and last-used IPs, so listing
> it is itself a privileged operation.

### SSO / identity-federation setup (platform administrator)

SSO **setup** for an organization (SAML, OIDC identity providers, verified
domains, SSO enforcement) is a platform-administrator operation, modeled on
Tenable Security Center's system-level Configuration. It lives only under the
admin realm, `/api/v1/admin/tenants/{tenantId}/sso/*` (next section). The former
tenant-context routes `/api/v1/settings/{saml,identity-providers,verified-domains}`
and the `PLATFORM_ADMIN_EMAILS` flag that guarded them were removed; no tenant
role, however high, can reach SSO setup. The SSO **login** flow
(`/api/v1/auth/sso/*`, `/api/v1/auth/saml/{org}/*`) is public and unchanged.

### Platform administrator identity (RFC-022)

A platform administrator is a `users` account linked to an `admin_users` row
(`admin_users.user_id`) that holds the role (`super_admin` > `ops_admin` >
`readonly`), the TOTP second factor and the admin audit trail. It signs in on the
normal `/login`, then `POST /api/v1/admin/auth/session` (refresh-token cookie)
and `POST /api/v1/admin/auth/mfa` open a console session. Rules:

- **Belongs to no organization.** A trigger on `tenant_members` rejects a
  membership for a linked account (SQLSTATE 23514, surfaced as 409), and an
  account with memberships cannot be linked. This is what keeps a tenant
  role and the platform role from ever meeting in one principal.
- **Password sign-in only.** A session created by SSO, SAML or a social provider
  cannot open the console, so no organization's IdP can authenticate an
  administrator.
- **TOTP always.** The `/login` session alone reaches nothing under
  `/api/v1/admin/*`; only a verified console session does (there are no
  admin API keys).
- Provisioning is `POST /api/v1/admin/administrators` (super admin), or
  `bootstrap-admin` for the first one and its break-glass backup. Rows without
  a `user_id` (former API-key identities) were deactivated by migration 000227.
- **Temporary password gate.** A provisioned account has
  `password_change_required`; a password-authenticated console session can then
  call only `GET /auth/validate` and `POST /auth/password` (403
  `PASSWORD_CHANGE_REQUIRED` otherwise).

#### Break-glass administrators and the platform IdP (RFC-022 revision 4)

- **Platform IdP** (`platform_identity_provider`, one OIDC provider, not
  tenant-scoped) is the only IdP that can open the console, and only for an
  administrator that already exists: matched by bound (`iss`, `sub`), or on
  first sign-in by verified email, then bound. No JIT creation. The console TOTP
  is still required after it unless a super admin trusts specific `acr`/`amr`
  values. Organization IdPs still cannot open the console.
- **Require IdP** refuses the local password path (`/auth/session`) for every
  administrator except break-glass ones.
- **Break-glass** administrators are local `super_admin`s that can never be
  bound to the IdP (database `CHECK`), are exempt from "require IdP", and every
  sign-in is audited high + alerted (`alert=break_glass_sign_in` + email).
- **Invariant** (server-side, under an advisory lock): at least one active,
  linked `super_admin` who can sign in locally always remains — while "require
  IdP" is in force, at least one break-glass `super_admin`. Delete, deactivate,
  demote and unmark that would break it return 409, as does turning on "require
  IdP" without one.

### Organizations — platform admin cross-tenant (RFC-022 Phase 2)

Under the admin realm (console session), never tenant-permission
gated. Organization-scoped SSO routes reuse the tenant SSO handlers through
`AdminTenantScope`, which checks the organization exists, sets it as the request
tenant, and **clears the user id** (the principal is the admin identity, not an
organization member, and those handlers write `created_by` columns that
reference `users(id)`). Writes are
recorded in `admin_audit_logs`, and in the organization's own audit log with
`actor_email = platform-admin:<email>` and `actor_id` NULL.

| Endpoint | Required Role |
|----------|---------------|
| `GET /api/v1/admin/tenants` (+ `/{tenantId}`) | any admin |
| `POST /api/v1/admin/tenants` | **ops_admin+** (audited; creates the owner's account when `owner_email` has none) |
| `GET /api/v1/admin/tenants/{tenantId}/users` | any admin |
| `POST /api/v1/admin/tenants/{tenantId}/users` | **ops_admin+** (audited; RFC-025) |
| `GET /api/v1/admin/tenants/{tenantId}/sso/{saml,identity-providers,verified-domains,enforcement}` | any admin |
| `PUT/POST/DELETE` on those SSO resources | **super_admin** (audited) |

**Tenant-side counterparts:**
- `PATCH /tenants/{t}/settings/security` refuses `sso_enforced` with 403.
  Enforcement is set only through `PUT /admin/tenants/{tenantId}/sso/enforcement`,
  which keeps the "usable SSO path required" guard.
- With `TENANT_CREATION_MODE=admin_only`, both self-service creation paths
  (`POST /api/v1/tenants` and `POST /api/v1/auth/create-first-team`) return
  403. Only `POST /admin/tenants` creates organizations. The mode is published
  as `tenant_creation_mode` on the public `GET /api/v1/auth/providers`.

### Metrics Endpoint (`GET /metrics`)

`/metrics` (Prometheus) is **not public by default**. It is gated by
`MetricsConfig`:

| `METRICS_PUBLIC` | `METRICS_TOKEN` | Behavior |
|------------------|-----------------|----------|
| `false` (default) | set | Requires `Authorization: Bearer <token>` (or `X-Metrics-Token`). Missing/wrong → 404 |
| `false` (default) | empty | Endpoint disabled (fail closed, 404) |
| `true` | — | Open, no auth (legacy; use only when firewalled to an internal scrape network) |

`/health` and `/ready` remain public. Configure the scraper's bearer token to
match `METRICS_TOKEN`.

## Organization access policy (RFC-025)

Two per-organization policies (`Security.AllowedDomains`, `Security.IPWhitelist`,
owner-managed) are enforced, not just stored. See
[user-onboarding.md](./user-onboarding.md).

- **Allowed email domains** gate every way into the organization: invitations
  (create and accept), invited registration, administrator-created users,
  `AddMember`/SCIM, and SSO just-in-time provisioning.
- **IP allowlist**: `middleware.IPAllowlistGate` runs on every user-token
  request (in `buildBaseMiddlewares` for the token's organization and after
  `RequireMembership` on `/tenants/{tenant}` for the URL organization). Not
  applied to sensor/agent or tenant API keys, the admin console, or public
  routes. 403 `IP_NOT_ALLOWED`; lookup errors fail closed; client IP from
  `httpsec.ClientIP` (trusted proxies only).
- **Self-registration** (`POST /auth/register`) is off unless
  `AUTH_ALLOW_REGISTRATION=true`; a pending invitation for the same email opens
  it for that person only.

## Module-Gate Layer (per-tenant feature gating)

Above the permission and role checks there is a third, orthogonal layer: the
**module gate**. `middleware.ModuleGate.RequireModule(moduleID)`
(`internal/infra/http/middleware/module_gate.go`) wraps a route group and returns
`403 MODULE_NOT_ENABLED` when the tenant has explicitly disabled that product
module. It is wired onto **26 route groups** in
`internal/infra/http/routes/routes.go` — e.g. `attack_surface`, `exposures`,
`suppressions`, `remediation`, `compliance`, `pentest`, `threat_intel`,
`reports`, `ctem_cycles`, `attacker_profiles`, `business_services`,
`compensating_controls`, `priority_rules`, `scope_config`, `components`,
`relationships`, `credentials`, `workflows`, `integrations`, `scan_pipelines`,
`scanner_templates`, `template_sources`, `attack_simulation`, `control_testing`,
`branches`, `iocs`.

**This is a feature gate, not a security boundary, and it is deliberately
fail-open.** A nil gate, missing provider, empty tenant, a core module, or any
lookup miss all resolve to "enabled" — only an explicitly-disabled non-core
module returns 403. Disabled sets are cached per tenant with a short TTL (60s
default) and invalidated on toggle. Permission and tenant-isolation checks are
the real access-control boundary; the gate only hides modules a tenant has
turned off. Core modules (see `module.IsCoreModule`) can never be gated off.

## Middleware Reference

### Permission Middleware

```go
// Single permission required
middleware.Require(permission.AssetsRead)

// Any of the permissions (OR)
middleware.RequireAny(permission.AssetsRead, permission.FindingsRead)

// All permissions required (AND)
middleware.RequireAll(permission.AssetsWrite, permission.FindingsWrite)
```

### Role Middleware (Team Context)

```go
// Specific roles required (from database membership)
middleware.RequireTeamRole(tenant.RoleOwner, tenant.RoleAdmin)

// Minimum role level (uses hierarchy)
middleware.RequireMinTeamRole(tenant.RoleAdmin)  // admin or owner

// Shortcuts
middleware.RequireTeamAdmin()   // owner or admin
middleware.RequireTeamOwner()   // owner only
middleware.RequireTeamWrite()   // owner, admin, or member
```

### Tenant Middleware

```go
// JWT-based tenant (from token claims)
middleware.RequireTenant()

// URL-based tenant (from path parameter)
middleware.TenantContext(tenantRepo)
middleware.RequireMembership(tenantRepo)
```

## Implementation Pattern

### Permission-based Routes (Recommended)

```go
router.Group("/api/v1/assets", func(r Router) {
    // Read operations
    r.GET("/", h.List, middleware.Require(permission.AssetsRead))
    r.GET("/{id}", h.Get, middleware.Require(permission.AssetsRead))

    // Write operations
    r.POST("/", h.Create, middleware.Require(permission.AssetsWrite))
    r.PUT("/{id}", h.Update, middleware.Require(permission.AssetsWrite))

    // Delete operations
    r.DELETE("/{id}", h.Delete, middleware.Require(permission.AssetsDelete))
}, authMiddleware, userSyncMiddleware, middleware.RequireTenant())
```

### Role-based Routes (Team Management)

```go
router.Group("/api/v1/tenants/{tenant}", func(r Router) {
    // Read operations - any member
    r.GET("/members", h.ListMembers)

    // Admin operations
    r.PATCH("/", h.Update, middleware.RequireTeamAdmin())
    r.POST("/members", h.AddMember, middleware.RequireTeamAdmin())

    // Owner-only operations
    r.DELETE("/", h.Delete, middleware.RequireTeamOwner())
}, authMiddleware, userSyncMiddleware, tenantContext, requireMembership)
```

## Role Hierarchy

```
owner (4) ─┬─ Can do everything
           │
admin (3) ─┼─ Can manage team members and settings
           │
member (2) ┼─ Can create/edit resources
           │
viewer (1) ┴─ Can only view resources
```

## Security Considerations

1. **Tenant Isolation**: Access tokens are scoped to a specific tenant. Users must exchange their refresh token for a tenant-scoped access token.

2. **Permission Validation**: The access token carries the user's full permission
   array, so the hot path checks permissions in-token with no per-request DB read.
   To close the stale-token window, a per-user **permission version** (Redis `INCR`)
   is bumped on any grant/revoke; a version mismatch makes `EnrichPermissions`
   re-resolve the effective permission set **from the database** and overwrite the
   request context, and a stale-version **write** is rejected with `409` rather than
   run on old permissions. `RevokeAllSessions` forces immediate re-auth. So the
   token is the fast path, but the database is the source of truth — see
   [permission-realtime-sync.md](./permission-realtime-sync.md).

3. **IDOR Prevention**: JWT-based tenant routes eliminate IDOR by design - users can only access their current tenant's data.

4. **Team Management Security**: Team operations use database-based membership verification via `RequireMembership` middleware.

5. **Owner Protection**: Team owners cannot be demoted or removed. Only team deletion removes the owner.

6. **Invitation Security**: Invitations are validated against the accepting user's email address.

## API Routes Summary

```
Public (No Auth):
├── GET  /health
├── GET  /ready
├── GET  /metrics
└── POST /api/v1/auth/*

User Profile (JWT Required):
└── /api/v1/users/me/*

JWT-Tenant Routes (Permission-based):
├── /api/v1/assets/*           → assets:read/write/delete
├── /api/v1/components/*       → components:read/write/delete
├── /api/v1/findings/*         → findings:read/write/delete
├── /api/v1/vulnerabilities/*  → vulnerabilities:read/write/delete
└── /api/v1/dashboard/*        → dashboard:read

URL-Tenant Routes (Role-based):
├── /api/v1/tenants                      → Any authenticated
├── /api/v1/tenants/{tenant}/members     → viewer+ (R), admin+ (W)
├── /api/v1/tenants/{tenant}/invitations → viewer+ (R), admin+ (W)
└── /api/v1/tenants/{tenant}             → admin+ (U), owner (D)

Invitations:
└── /api/v1/invitations/{token}/*        → Any authenticated
```

Legend: (R) = Read, (W) = Write, (U) = Update, (D) = Delete

## Settled model — the rules we lock going forward

The authorization model was reviewed end-to-end (2026-09, `docs/authz-audit.md`)
and standardized. The following are **decisions**, not accidents — each was made
deliberately and, where a design choice was involved, benchmarked against
Tenable.sc's RBAC.

1. **Allow-only, default-deny.** A user's effective permission set is the *union*
   of what their roles grant. There is **no deny-override**: a permission-set can
   only *add* capability, never subtract it at the enforcement layer. A "deny" that
   appears in the UI/permission-set model is advisory (Layer-2), it does **not**
   gate the API. This mirrors Tenable.sc, which is purely additive with no
   deny-override. → we will **not** build a permission-set deny-gate.

2. **Backend is the only authority.** The frontend hides controls the user lacks
   perms for as a UX nicety; it is never the boundary. Every mutation is
   independently gated server-side. UI perm checks that duplicate a server gate are
   convenience, not security.

3. **Effective permissions come from the database, not blindly from the token.**
   The token is the fast path; the per-user permission version + `EnrichPermissions`
   re-resolution + `409` on stale writes make the DB the source of truth (see
   Security Consideration #2 and `permission-realtime-sync.md`).

4. **Granular over coarse.** Action routes are gated on the most precise permission
   that describes the action (e.g. `findings:status`, not `findings:write`), so the
   role matrix tells the truth about who can do what. Tightening a role's grant is a
   *product* decision made via seed/migration, never by silently widening a route's
   gate.

5. **No time-limited grants.** There is no `expires_at` on role assignments.
   Tenable.sc has no expiring grants either; revocation is immediate via
   `RevokeAllSessions` + version bump. → we will **not** build expiring grants (YAGNI).

6. **The module gate is a feature flag, not a security boundary.** It is fail-open
   by design (see "Module-Gate Layer"). Never rely on it to protect data — that is
   the job of the permission gate + tenant isolation.

### Known, deliberate gaps (do not "fix" without a decision)

- **Two admin oracles.** Permission-based `IsAdmin` (from the token) and live-DB
  team-role (`RequireTeamAdmin/Owner`) are separate mechanisms and can, in edge
  cases, disagree. Unifying them onto live membership (which would also fix
  `IsOwner` under OIDC) is a phased refactor — **deferred** because a missing
  membership middleware on any chain would 403 a whole route group.
- **Data-scope is fail-open.** `user_accessible_assets` narrows assets/findings for
  non-admins, but an *empty* assignment means "see all", and `GetByID` is unscoped.
  Flipping to fail-closed (Tenable's default "No Access") is behavior-changing —
  **deferred**, needs signoff.
- **RLS is shadow-mode.** ~99 policies exist, 0 tables have RLS enabled. This is
  intentional (staged rollout), not a dead control. Tenant isolation is enforced by
  convention (`WHERE tenant_id = $n`) today; do not assume RLS backstops it.

## CI invariants that keep this from drifting

Two tests fail the build if the model erodes. Treat them as executable spec:

| Invariant | Test | What it guarantees |
|-----------|------|--------------------|
| **Every route is gated or explicitly allowlisted** | `tests/unit/route_authz_coverage_test.go` (AUTHZ-02) | A go/ast walk of `routes/*.go` resolves chi `.Group` nesting + inherited gates; any route with no `Require*`/`RequireTeam*`/`RequireRole` and not in `allowlistPrefixes` fails the build, naming the route. Removing one `Require(...)` → red. |
| **Go permission registry ≡ DB seed** | `tests/unit/permission_catalog_sync_test.go` (AUTHZ-17) | Parses the seed migrations and asserts set-equality with `permission.AllPermissions()`. A permission added to code but not seeded (or vice-versa) → red. |

The permission strings themselves are also mirrored in the UI (TS constants); the
sync test covers Go↔DB, and code review covers UI drift until the monorepo contract
codegen (RFC-020) subsumes both.

## How to … (recipes that stay inside the invariants)

### Add a new permission

1. Add the constant to `pkg/domain/permission/permission.go` **and** include it in
   `AllPermissions()`.
2. Add the same string to the DB seed (a new numbered migration under
   `migrations/` — additive `INSERT ... ON CONFLICT DO NOTHING`, with a matching
   `.down.sql`).
3. Add the string to the UI permission constants so the frontend can gate on it.
4. Map it into the default roles that should hold it (`role_mapping.go` + seed).
5. `go test ./tests/unit/...` — the catalog-sync test proves 1↔2 agree.

### Gate a new route

- Attach the least-privilege permission at registration:
  `r.POST("/", h.Create, middleware.Require(permission.FooWrite))`.
- For team-management routes under `/tenants/{tenant}`, use `RequireTeamAdmin()` /
  `RequireTeamOwner()` (live membership) instead of a permission.
- If the whole route group belongs to a product module, wrap it with
  `ModuleGate.RequireModule(moduleID)` **in addition to** (never instead of) the
  permission gate.
- If the route is legitimately unauthenticated or self-scoped (auth, `/users/me`,
  agent-key, SCIM, webhook, admin-realm, health), add it to `allowlistPrefixes` in
  `route_authz_coverage_test.go` **with a reason comment** — that is the only way to
  pass the coverage gate without a gate, and it forces the decision to be explicit.

### Enforce object-level (row) authorization

Permission gates answer "may this user do this *kind* of thing"; they do **not**
answer "may they touch *this* row". For that:

- Always scope repository reads/writes by `tenant_id` (every mutating query must
  carry `AND tenant_id = $n` — see `ScanRepository.Update`, AUTHZ-10). Do not trust
  an id from the URL to already be tenant-scoped.
- For non-admin data-scope narrowing on assets/findings, go through
  `user_accessible_assets` (note its fail-open caveat above).
- Never authorize a mutation off the request body's tenant/owner fields — derive the
  principal's tenant from the authenticated context (or, for agents, from the agent
  key), never from client-supplied data.
