# Architecture Overview

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.26+ |
| HTTP Router | Chi v5 (with abstraction layer) |
| HTTP Handlers | Standard `net/http` signature |
| Authentication | Local accounts (JWT) / OAuth2 (Google, GitHub, Microsoft) / per-organization OIDC (e.g. Entra ID) and SAML SSO |
| Validation | go-playground/validator/v10 |
| Database | PostgreSQL 17 |
| Cache | Redis 7 |
| Logging | Structured logging (slog) |
| Migrations | golang-migrate |

## System Diagram

```
 Browser ──► Web console (Next.js, same-origin proxy)
                    │  /api/*
                    ▼
 ┌───────────────────────────────────────────────┐
 │ OpenCTEM API (Go)                             │
 │  /api/v1/*        console and integrations    │
 │  /api/v2/sensor/* sensor protocol             │
 │  controllers      scheduled background jobs   │
 └──────┬──────────────┬──────────────┬──────────┘
        ▼              ▼              ▼
   PostgreSQL 17    Redis 7     External systems
                                (ticketing, notifications,
                                 SIEM, importers, SSO IdPs)

 Customer networks
 ┌───────────────────────────────────────────────┐
 │ Sensors (openctemio/sensor, built on sdk-go)  │
 │  roles: scanner · collector · agent-mode      │
 │  pull work from /api/v2/sensor, run tools,    │
 │  report results (CTIS) back                   │
 └───────────────────────────────────────────────┘
```

## Sensors

Scanning and collection run in **sensors**, not in the API. A sensor runs in the
customer's network (or as a platform sensor operated by the platform), has its
own identity ([agent-identity.md](agent-identity.md)), pulls commands over the
sensor protocol v2 and reports results that the API ingests through the CTIS
contract. Roles: **scanner** (runs tools such as nuclei, httpx, semgrep, trivy),
**collector** (pulls data from other systems) and **agent-mode** (endpoint).
Scan zones route work to the sensors that can reach the targets
([scan-zones.md](scan-zones.md)). Full model: [sensors.md](sensors.md).

## Scan workflows

A **scan workflow** is a reusable, multi-step definition; a **scan** applies a
workflow (or a single tool) to targets on a schedule or on demand; each
execution is a **scan run** made of **steps** and **tasks** dispatched to
sensors. Steps declare the tool and capabilities they need; a step only goes to
a sensor that advertises them.

```
Scan workflow: "Full Security Scan"
├── Step 1: SAST (semgrep)
├── Step 2: SCA (trivy)
├── Step 3: Secrets (betterleaks)
└── Step 4: Web checks (nuclei)
    └── depends_on: [Step 1, Step 2]
```

Lifecycle and states: [scan-lifecycle.md](scan-lifecycle.md); naming:
[scan-naming.md](scan-naming.md).

## Multi-Tenant Architecture

OpenCTEM is multi-tenant:
- Users sign in with a local account, OAuth, or their organization's SSO
- A user can belong to several **organizations** (shown as teams in parts of the UI)
- Organizations are **tenants** in code and database
- Each tenant has members with roles (owner, admin, member, viewer, and custom roles)
- Every tenant-scoped query carries `tenant_id`; PostgreSQL RLS policies exist
  but are not enabled yet ([rls-rollout.md](rls-rollout.md))

### Data Model

```
User                Membership               Tenant
┌──────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ id (sub)     │───<│ user_id          │    │ id               │
│ email        │    │ tenant_id        │>───│ name             │
│ name         │    │ role             │    │ slug             │
└──────────────┘    │ joined_at        │    │ plan             │
                    └──────────────────┘    │ created_at       │
                                            └──────────────────┘
                                                     │
                    ┌────────────────────────────────┘
                    ▼
             ┌──────────────┐
             │   Assets     │
             │  tenant_id   │ ← All business data scoped by tenant
             └──────────────┘
```

### Roles & Permissions

| Role | Permissions |
|------|------------|
| owner | Full control, can delete team, manage billing |
| admin | Manage members, invite users, all data operations |
| member | Read/write data, cannot manage members |
| viewer | Read-only access |

### API Routes

```
# Tenant management (authenticated)
POST   /api/v1/tenants              # Create tenant
GET    /api/v1/tenants              # List user's tenants
GET    /api/v1/tenants/{tenant}     # Get tenant by ID/slug

# Tenant-scoped (requires membership)
PATCH  /api/v1/tenants/{tenant}     # Update tenant
DELETE /api/v1/tenants/{tenant}     # Delete tenant

# Member management
GET    /api/v1/tenants/{tenant}/members
POST   /api/v1/tenants/{tenant}/members
PATCH  /api/v1/tenants/{tenant}/members/{id}
POST   /api/v1/organization/members/{id}/offboard   # step-up

# Invitations
POST   /api/v1/tenants/{tenant}/invitations
POST   /api/v1/invitations/lookup       {"token": ...}
POST   /api/v1/invitations/accept       {"token": ...}

# Tenant-scoped resources use the tenant of the access token
GET    /api/v1/assets
POST   /api/v1/assets
...
```

### Naming Convention

| Context | Term |
|---------|------|
| UI/Frontend | Organization (Team in older screens) |
| API Routes | /tenants |
| Database tables | tenants, tenant_members |
| Go code | tenant.Tenant, TenantService |

## Clean Architecture Layers

```
┌─────────────────────────────────────────────────────────┐
│                     cmd/server                           │
│                   (Entry Point)                          │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                  internal/infra                          │
│            (HTTP, PostgreSQL adapters)                   │
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │   HTTP      │  │  Postgres   │  │   Middleware    │  │
│  │  Handlers   │  │   Repos     │  │  (CORS,Log...)  │  │
│  │             │  │             │  │                 │  │
│  └─────────────┘  └─────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   internal/app                           │
│      (application services, one package per context)    │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ AssetService │  │ ScopeService │  │ VulnService  │   │
│  │ TenantService│  │ AuditService │  │ SLAService   │   │
│  │ AuthService  │  │ UserService  │  │ + 10 more... │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                    pkg/domain                            │
│              (bounded contexts)                          │
│              NO EXTERNAL DEPENDENCIES                    │
│                                                          │
│  ┌──────────┐ ┌────────────┐ ┌─────────────┐ ┌────────┐ │
│  │ shared/  │ │ asset/     │ │ assetgroup/ │ │ scope/ │ │
│  │ - ID     │ │ - Entity   │ │ - Entity    │ │ Target │ │
│  │ - Errors │ │ - Repo     │ │ - Repo      │ │ Excl.  │ │
│  └──────────┘ └────────────┘ └─────────────┘ │ Sched. │ │
│                                              └────────┘ │
│  ┌──────────┐ ┌────────────┐ ┌─────────────┐ ┌────────┐ │
│  │ tenant/  │ │ vuln./     │ │ sensor/     │ │scanrun/│ │
│  │ Member   │ │ Finding    │ │ Sensor      │ │Workflow│ │
│  │ Invite   │ │ Comment    │ │ Repository  │ │Step,Run│ │
│  └──────────┘ └────────────┘ └─────────────┘ └────────┘ │
│  ┌──────────┐ ┌────────────┐ ┌─────────────┐ ┌────────┐ │
│  │ scmconn/ │ │ command/   │ │ permission/ │ │ + more │ │
│  │ OAuth    │ │ Source cmd │ │ RBAC        │ │        │ │
│  └──────────┘ └────────────┘ └─────────────┘ └────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Project Structure

See [project-structure.md](project-structure.md).

## Design Principles

### 1. Hexagonal Architecture (Ports & Adapters)

- **Domain** at the center with no external dependencies
- **Ports** (interfaces) defined in domain layer
- **Adapters** implement ports in infrastructure layer
- **Dependencies point inward** - outer layers depend on inner layers

```
Hexagonal / Ports & Adapters
├── Port:    Router interface (router.go)
├── Adapter: Chi implementation (chi_router.go)
├── DTO:     Request/Response structs in handler
└── Handler: Standard net/http signature
```

### 2. Domain-Driven Design (DDD)

- **Entities** with identity and behavior (Asset)
- **Value Objects** for immutable concepts (AssetType, Criticality, Status)
- **Repository interfaces** for persistence abstraction
- **Domain errors** for business rule violations

### 3. Transport DTO Pattern

- **Request DTOs** in handler (JSON tags, validation)
- **Application DTOs** in service (business input/output)
- **Domain Entities** pure business logic
- **Response DTOs** for API responses

### 4. Dependency Injection

- Services receive dependencies via constructors
- No global state or singletons
- Easy to test with mocks

### 5. Separation of Concerns

- **Domain**: Business rules only
- **Application**: Use case orchestration
- **Infrastructure**: External system integration

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Chi + Abstraction | Clean syntax, net/http compatible, swappable |
| net/http handlers | Standard signature, no framework lock-in |
| Router interface | Can swap Chi/stdlib without code changes |
| ID in domain | Entity identity is a domain concept |
| Pagination in pkg | Reusable utility, not domain logic |
| Structured logging | Consistent, searchable logs |

## Related Documents

- [Project Structure](project-structure.md)
- [Clean Architecture Details](clean-arch.md)
- [Notification System](notification-system.md)
- [Scan Lifecycle](scan-lifecycle.md)
- [Scan Orchestration (older walkthrough)](scan-orchestration.md)
- [Scan Zones](scan-zones.md)
- [Tool Availability](tool-availability.md)
- [Sensor ↔ Platform Trust](sensor-platform-trust.md)
- [Signed Jobs: the Job Signer](job-signing.md)
- [Audit Hash Chain](audit-hash-chain.md)
- [CTEM-ID Catalog](ctem-id-catalog.md)
- [Certificate-Transparency Monitoring](certificate-transparency-monitoring.md)
- [External Attack Surface Management (EASM)](easm.md)
- [EASM DNS-only checks (dangling DNS, email posture)](easm-dns-checks.md)
- [Criticality Propagation](criticality-propagation.md)
- [Sensor Result Binding](sensor-result-binding.md)
- [ADR-001: Use Standard net/http](decisions/001-use-stdlib-http.md)
