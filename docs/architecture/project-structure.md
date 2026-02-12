# Project Structure

Complete file structure for the OpenCTEM project.

## Root Structure

```
openctem/
├── cmd/                    # Application entry points
├── api/                    # API definitions (OpenAPI)
├── internal/               # Private application code
├── pkg/                    # Public shared libraries
├── migrations/             # Database migrations
├── tests/                  # Integration tests
├── scripts/                # Utility scripts
├── docs/                   # Documentation
├── deploy/                 # Deployment configs (K8s, Helm, Terraform)
├── .github/                # CI/CD workflows
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile              # Single multi-target Dockerfile
├── docker-compose.yml
├── docker-compose.dev.yml
├── docker-compose.prod.yml
├── .env.example
├── .air.toml
├── .gitignore
├── .golangci.yml
└── README.md
```

---

## cmd/

Application entry points.

```
cmd/
└── server/
    └── main.go             # HTTP server entry point
```

---

## internal/

Private application code organized by Clean Architecture layers.

```
internal/
├── domain/                 # Domain layer (innermost)
│   ├── shared/             # Shared domain types
│   │   ├── id.go           # UUID-based entity identifier
│   │   └── errors.go       # Domain error definitions
│   │
│   ├── asset/              # Asset bounded context
│   │   ├── entity.go       # Asset entity with behavior
│   │   ├── value_objects.go # AssetType, Criticality, Status
│   │   ├── repository.go   # Repository interface + Filter
│   │   └── errors.go       # Asset-specific errors
│   │
│   ├── assetgroup/         # Asset grouping/organization
│   │   ├── entity.go       # AssetGroup entity
│   │   └── repository.go   # Repository interface
│   │
│   ├── assettype/          # Asset type definitions
│   │   ├── entity.go       # AssetType, Category entities
│   │   └── repository.go   # Repository interfaces
│   │
│   ├── audit/              # Audit logging
│   │   ├── entity.go       # AuditLog entity
│   │   └── repository.go   # Repository interface
│   │
│   ├── branch/             # Git branch management
│   │   ├── entity.go       # Branch entity
│   │   └── repository.go   # Repository interface
│   │
│   ├── component/          # Software components (SBOM)
│   │   ├── entity.go       # Component entity
│   │   └── repository.go   # Repository interface
│   │
│   ├── permission/         # Permission definitions
│   │   └── permission.go   # Permission constants
│   │
│   ├── scmconnection/      # SCM integrations (GitHub, GitLab)
│   │   ├── entity.go       # SCMConnection entity
│   │   └── repository.go   # Repository interface
│   │
│   ├── scope/              # Scope configuration (CTEM Scoping)
│   │   ├── entity.go       # Target, Exclusion, Schedule entities
│   │   ├── repository.go   # Repository interfaces
│   │   └── errors.go       # Scope-specific errors
│   │
│   ├── session/            # User sessions
│   │   ├── entity.go       # Session entity
│   │   └── repository.go   # Repository interface
│   │
│   ├── sla/                # SLA management
│   │   ├── entity.go       # SLA entity
│   │   └── repository.go   # Repository interface
│   │
│   ├── tenant/             # Multi-tenant context
│   │   ├── entity.go       # Tenant, Membership entities
│   │   ├── invitation.go   # Invitation entity
│   │   └── repository.go   # Repository interfaces
│   │
│   ├── user/               # User management
│   │   ├── entity.go       # User entity
│   │   └── repository.go   # Repository interface
│   │
│   └── vulnerability/      # Vulnerability tracking
│       ├── entity.go       # Vulnerability, Finding entities
│       ├── repository.go   # Repository interfaces
│       └── errors.go       # Vulnerability-specific errors
│
├── app/                    # Application layer (use cases)
│   ├── asset_service.go          # Asset operations
│   ├── asset_group_service.go    # Asset group management
│   ├── asset_type_service.go     # Asset type management
│   ├── audit_service.go          # Audit logging
│   ├── auth_service.go           # Authentication
│   ├── branch_service.go         # Branch management
│   ├── component_service.go      # Component management
│   ├── dashboard_service.go      # Dashboard aggregations
│   ├── email_service.go          # Email notifications
│   ├── finding_comment_service.go # Finding comments
│   ├── oauth_service.go          # OAuth/SCM integrations
│   ├── scm_connection_service.go # SCM connections
│   ├── scope_service.go          # Scope configuration
│   ├── session_service.go        # Session management
│   ├── sla_service.go            # SLA management
│   ├── tenant_service.go         # Tenant operations
│   ├── user_service.go           # User management
│   └── vulnerability_service.go  # Vulnerability tracking
│
├── config/                 # Configuration
│   └── config.go           # Environment-based config loading
│
└── infra/                  # Infrastructure layer (outermost)
    ├── http/               # HTTP adapter
    │   ├── server.go       # HTTP server setup
    │   ├── router.go       # Router interface (abstraction)
    │   ├── chi_router.go   # Chi router implementation
    │   ├── request.go      # Request helpers (PathParam, QueryParam)
    │   ├── route_printer.go # Route debugging utilities
    │   │
    │   ├── routes/         # Route registration (organized by domain)
    │   │   ├── routes.go   # Main entry point, Handlers struct, Register()
    │   │   ├── admin.go    # Platform admin routes (/api/v1/admin/...)
    │   │   ├── auth.go     # Authentication routes
    │   │   ├── tenant.go   # Tenant management routes
    │   │   ├── assets.go   # Asset, Component, AssetGroup, Scope routes
    │   │   ├── scanning.go # Agent, Command, Scan, Pipeline, Tool routes
    │   │   ├── exposure.go # Exposure, ThreatIntel, Credential routes
    │   │   ├── access_control.go # Group, Role, Permission routes
    │   │   ├── platform.go # Platform agent/job routes (tenant-facing)
    │   │   └── misc.go     # Health, Docs, Dashboard, Audit, SLA routes
    │   │
    │   ├── handler/        # Request handlers
    │   │   ├── health_handler.go
    │   │   ├── auth_handler.go
    │   │   ├── asset_handler.go
    │   │   ├── asset_group_handler.go
    │   │   ├── scope_handler.go
    │   │   ├── vulnerability_handler.go
    │   │   ├── platform_agent_handler.go
    │   │   ├── platform_job_handler.go
    │   │   └── ...         # 40+ handlers
    │   │
    │   └── middleware/     # HTTP middleware
    │       ├── cors.go
    │       ├── logger.go
    │       ├── recovery.go
    │       ├── requestid.go
    │       ├── auth.go     # JWT authentication
    │       ├── tenant.go   # Tenant context
    │       └── platform_admin.go # Platform admin authorization
    │
    └── postgres/           # PostgreSQL adapter
        ├── connection.go   # Database connection pool
        ├── asset_repository.go
        ├── asset_group_repository.go
        ├── scope_target_repository.go
        ├── scope_exclusion_repository.go
        ├── scope_schedule_repository.go
        └── ...             # 15+ repositories
```

---

## pkg/

Public utilities that can be imported by other projects.

```
pkg/
├── apierror/
│   └── apierror.go         # API error response types
│
├── jwt/
│   └── jwt.go              # JWT token generation/validation
│
├── logger/
│   └── logger.go           # Structured logging wrapper (slog)
│
├── pagination/
│   └── pagination.go       # Pagination types and helpers
│
└── validator/
    └── validator.go        # Struct validation (go-playground/validator)
```

---

## api/

API specifications.

```
api/
└── openapi/
    └── openapi.yaml        # OpenAPI 3.1 specification
```

---

## migrations/

Database migrations using golang-migrate format.

```
migrations/
├── 000001_init_schema.up.sql    # Create tables
└── 000001_init_schema.down.sql  # Drop tables
```

---

## tests/

Test suites.

```
tests/
├── integration/
│   └── asset_test.go           # Asset integration tests
│
└── unit/
    ├── jwt_test.go             # JWT package tests
    ├── validator_test.go       # Validator package tests
    ├── middleware_test.go      # Auth middleware tests
    ├── asset_service_test.go   # Service layer tests
    └── asset_handler_test.go   # Handler tests
```

---

## scripts/

Utility scripts.

```
scripts/
├── migrate.sh              # Database migration runner
└── generate-mocks.sh       # Mock generation script
```

---

## .github/

GitHub Actions workflows.

```
.github/
└── workflows/
    └── ci.yml              # CI pipeline (test, lint, build)
```

---

## Docker Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Single multi-target build (base, development, builder, production) |
| `docker-compose.yml` | Base services (PostgreSQL, Redis) |
| `docker-compose.dev.yml` | Development app override (target: development) |
| `docker-compose.prod.yml` | Production app override (target: production) |

## deploy/

Future deployment configurations (currently empty, reserved for expansion).

```
deploy/
├── .gitkeep                # Placeholder
├── kubernetes/             # (future) K8s manifests
├── helm/                   # (future) Helm charts
└── terraform/              # (future) Infrastructure as code
```

---

## Config Files

| File | Purpose |
|------|---------|
| `go.mod` | Go module definition |
| `go.sum` | Dependency checksums |
| `Makefile` | Build and development commands |
| `.env.example` | Environment variables template |
| `.air.toml` | Hot reload configuration |
| `.gitignore` | Git ignore rules |
| `.golangci.yml` | Linter configuration |

---

## Layer Dependencies

```
┌─────────────────────────────────────────┐
│              cmd/server                  │
│            (Entry Point)                 │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│           internal/infra                 │
│    (HTTP handlers, PostgreSQL repo)      │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│            internal/app                  │
│       (Application services)             │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│           internal/domain                │
│   (Entities, Value Objects, Interfaces)  │
│         NO EXTERNAL DEPENDENCIES         │
└─────────────────────────────────────────┘
```

Dependency rule: Dependencies point inward only. Domain has no dependencies.
