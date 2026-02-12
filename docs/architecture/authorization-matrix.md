# Authorization Matrix

This document describes the complete authorization model for the OpenCTEM API.

## Overview

The system uses a **two-layer authorization model**:

1. **Permission-based Authorization**: Fine-grained permissions (`resource:action`) embedded in JWT tokens
2. **Role-based Authorization**: Team roles (owner, admin, member, viewer) for team management

## Authorization Models

### Permission-based (JWT Claims)

Permissions are included in the access token and checked using `middleware.Require()`:

| Permission | Description |
|------------|-------------|
| `assets:read` | View assets |
| `assets:write` | Create/update assets |
| `assets:delete` | Delete assets |
| `projects:read` | View projects |
| `projects:write` | Create/update projects |
| `projects:delete` | Delete projects |
| `components:read` | View components |
| `components:write` | Create/update components |
| `components:delete` | Delete components |
| `findings:read` | View findings |
| `findings:write` | Create/update findings |
| `findings:delete` | Delete findings |
| `vulnerabilities:read` | View CVE database |
| `vulnerabilities:write` | Manage CVE database |
| `vulnerabilities:delete` | Delete vulnerabilities |
| `dashboard:read` | View dashboard stats |

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
| `GET /metrics` | Prometheus metrics |
| `POST /api/v1/auth/register` | User registration |
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

#### Projects (`/api/v1/projects`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/projects` | `projects:read` |
| `GET /api/v1/projects/{id}` | `projects:read` |
| `POST /api/v1/projects` | `projects:write` |
| `PUT /api/v1/projects/{id}` | `projects:write` |
| `DELETE /api/v1/projects/{id}` | `projects:delete` |

#### Components (`/api/v1/components`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/components` | `components:read` |
| `GET /api/v1/components/{id}` | `components:read` |
| `POST /api/v1/components` | `components:write` |
| `PUT /api/v1/components/{id}` | `components:write` |
| `DELETE /api/v1/components/{id}` | `components:delete` |
| `GET /api/v1/projects/{id}/components` | `components:read` |

#### Findings (`/api/v1/findings`)

| Endpoint | Permission Required |
|----------|---------------------|
| `GET /api/v1/findings` | `findings:read` |
| `GET /api/v1/findings/{id}` | `findings:read` |
| `POST /api/v1/findings` | `findings:write` |
| `PATCH /api/v1/findings/{id}/status` | `findings:write` |
| `DELETE /api/v1/findings/{id}` | `findings:delete` |
| `GET /api/v1/projects/{id}/findings` | `findings:read` |

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
| `DELETE /api/v1/tenants/{tenant}` | **Team owner only** |

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

## Middleware Reference

### Permission Middleware

```go
// Single permission required
middleware.Require(permission.AssetsRead)

// Any of the permissions (OR)
middleware.RequireAny(permission.AssetsRead, permission.ProjectsRead)

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

2. **Permission Validation**: Permissions are validated from JWT claims on every request. No database lookup needed.

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
├── /api/v1/projects/*         → projects:read/write/delete
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
