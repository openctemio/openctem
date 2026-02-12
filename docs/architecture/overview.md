# Architecture Overview

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.25+ |
| HTTP Router | Chi v5 (with abstraction layer) |
| HTTP Handlers | Standard `net/http` signature |
| Authentication | Keycloak (RS256 JWKS) |
| Validation | go-playground/validator/v10 |
| Database | PostgreSQL 17 |
| Cache | Redis 7 |
| Logging | Structured logging (slog) |
| Migrations | golang-migrate |

## System Diagram

```
                                    ┌─────────────────────────────────────┐
┌──────────────┐                    │       OpenCTEM Control Plane        │
│   Clients    │                    ├─────────────────────────────────────┤
├──────────────┤                    │  HTTP API (REST)                    │
│  Web App     │───────────────────▶│  - /api/v1/agents/*                 │
│  Mobile App  │                    │  - /api/v1/pipelines/*              │
│  CLI         │                    │  - /api/v1/findings/*               │
└──────────────┘                    │  - /api/v1/agent/* (agent API)      │
                                    └──────────────┬──────────────────────┘
                                                   │
                        ┌──────────────────────────┼──────────────────────────┐
                        ▼                          ▼                          ▼
                 ┌──────────┐               ┌──────────┐               ┌──────────────┐
                 │ Postgres │               │  Redis   │               │  Connectors  │
                 │   (DB)   │               │ (Cache)  │               │ (Wiz,Tenable)│
                 │   + RLS  │               └──────────┘               └──────────────┘
                 └──────────┘

┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              Tenant Infrastructure                                   │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐    │
│  │    Runner      │  │    Worker      │  │   Collector    │  │    Sensor      │    │
│  │ (CI/CD scan)   │  │  (daemon)      │  │   (cloud)      │  │  (EASM)        │    │
│  │                │  │                │  │                │  │                │    │
│  │ - Poll tasks   │  │ - Poll tasks   │  │ - Poll tasks   │  │ - Poll tasks   │    │
│  │ - Run scans    │  │ - Execute jobs │  │ - Collect data │  │ - EASM recon   │    │
│  │ - Report back  │  │ - Report back  │  │ - Report back  │  │ - Report back  │    │
│  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘    │
│          │                   │                   │                   │             │
│          └───────────────────┴───────────────────┴───────────────────┘             │
│                                         │                                          │
│                            ┌────────────▼────────────┐                             │
│                            │   OpenCTEM SDK (Go)     │                             │
│                            │   - API key auth        │                             │
│                            │   - Task polling        │                             │
│                            │   - Finding submission  │                             │
│                            └─────────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Distributed Agent Architecture

OpenCTEM uses a distributed agent model where:
- **Control Plane** (this server) manages agents, pipelines, and findings
- **Agents** run on tenant infrastructure using the OpenCTEM SDK
- **Agents poll** for tasks based on their capabilities
- **Data flows** from agents back to the control plane via REST API

### Agent Types

| Type | Description | Use Case |
|------|-------------|----------|
| `runner` | CI/CD one-shot | SAST, DAST, SCA scans in CI/CD |
| `worker` | Server-controlled daemon | Continuous scanning |
| `collector` | Data collection agent | Cloud inventory, vulnerability feeds |
| `sensor` | EASM sensor | External attack surface monitoring |

### Capability-Based Task Assignment

Agents declare their capabilities (e.g., `sast`, `dast`, `sca`, `infra`) and tools (e.g., `semgrep`, `trivy`, `nuclei`). The control plane assigns tasks to agents with matching capabilities.

```
Pipeline Step: SAST Analysis
├── Capabilities required: ["sast"]
├── Tool preferred: "semgrep"
└── Agents matched: [runner-1, runner-3]
```

## Pipeline Orchestration

Pipelines orchestrate multi-step security workflows:

```
Pipeline Template: "Full Security Scan"
├── Step 1: SAST Analysis (semgrep)
├── Step 2: SCA Scan (trivy)
├── Step 3: Secrets Detection (trufflehog)
└── Step 4: Infrastructure Scan (nuclei)
    └── depends_on: [Step 1, Step 2]

Pipeline Run
├── Created by: manual trigger
├── Asset: repo-xyz
├── Status: running
└── Step Runs:
    ├── step-1: completed (15 findings)
    ├── step-2: completed (3 findings)
    ├── step-3: running
    └── step-4: pending
```

## Multi-Tenant Architecture

OpenCTEM uses a multi-tenant SaaS model where:
- Users authenticate via Keycloak
- Users can belong to multiple **Teams** (displayed in UI)
- Teams are called **Tenants** in code/database
- Each tenant has members with roles (owner, admin, member, viewer)
- Data is isolated per tenant using PostgreSQL Row-Level Security (RLS)

### Data Model

```
User (Keycloak)     Membership (App DB)      Tenant (App DB)
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
DELETE /api/v1/tenants/{tenant}/members/{id}

# Invitations
POST   /api/v1/tenants/{tenant}/invitations
GET    /api/v1/invitations/{token}
POST   /api/v1/invitations/{token}/accept

# Tenant-scoped resources (future)
GET    /api/v1/tenants/{tenant}/assets
POST   /api/v1/tenants/{tenant}/assets
...
```

### Naming Convention

| Context | Term |
|---------|------|
| UI/Frontend | Team |
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
│  │  (15+)      │  │   (15+)     │  │                 │  │
│  └─────────────┘  └─────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   internal/app                           │
│              (18 Application Services)                   │
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
│                  internal/domain                         │
│          (17 Bounded Contexts)                           │
│              NO EXTERNAL DEPENDENCIES                    │
│                                                          │
│  ┌──────────┐ ┌────────────┐ ┌─────────────┐ ┌────────┐ │
│  │ shared/  │ │ asset/     │ │ assetgroup/ │ │ scope/ │ │
│  │ - ID     │ │ - Entity   │ │ - Entity    │ │ Target │ │
│  │ - Errors │ │ - Repo     │ │ - Repo      │ │ Excl.  │ │
│  └──────────┘ └────────────┘ └─────────────┘ │ Sched. │ │
│                                              └────────┘ │
│  ┌──────────┐ ┌────────────┐ ┌─────────────┐ ┌────────┐ │
│  │ tenant/  │ │ vuln./     │ │ agent/      │ │pipeline│ │
│  │ Member   │ │ Finding    │ │ Agent       │ │Template│ │
│  │ Invite   │ │ Comment    │ │ Repository  │ │Step,Run│ │
│  └──────────┘ └────────────┘ └─────────────┘ └────────┘ │
│  ┌──────────┐ ┌────────────┐ ┌─────────────┐ ┌────────┐ │
│  │ scmconn/ │ │ command/   │ │ permission/ │ │ + more │ │
│  │ OAuth    │ │ Source cmd │ │ RBAC        │ │        │ │
│  └──────────┘ └────────────┘ └─────────────┘ └────────┘ │
└─────────────────────────────────────────────────────────┘
```

## Project Structure

```
openctem/
├── cmd/server/              # Application entry point
├── internal/
│   ├── domain/              # Core business logic
│   │   ├── shared/          # Shared types (ID, errors)
│   │   ├── asset/           # Asset bounded context
│   │   └── tenant/          # Multi-tenant context
│   ├── app/                 # Application services
│   │   ├── asset_service.go
│   │   └── tenant_service.go
│   ├── config/              # Configuration
│   └── infra/               # Infrastructure adapters
│       ├── http/            # HTTP server, handlers
│       │   ├── handler/     # tenant_handler, asset_handler
│       │   └── middleware/  # tenant, auth middleware
│       └── postgres/        # Database repository
├── pkg/                     # Public utilities
│   ├── logger/              # Structured logging
│   ├── pagination/          # Pagination helpers
│   └── apierror/            # API error types
├── migrations/              # Database migrations
├── api/openapi/             # OpenAPI specification
├── tests/                   # Integration tests
└── docs/                    # Documentation
```

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
- [Scan Orchestration](scan-orchestration.md)
- [ADR-001: Use Standard net/http](decisions/001-use-stdlib-http.md)
