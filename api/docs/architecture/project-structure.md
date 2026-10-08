# Project Structure

The layout of `api/` in the `openctemio/openctem` monorepo. The web console is
`web/` (see [web/docs/ARCHITECTURE.md](../../../web/docs/ARCHITECTURE.md)); CI
workflows, git hooks and the root `Makefile` are at the repository root.

## api/

```
api/
├── cmd/                    # Entry points
├── internal/               # Application code (not importable from outside the module)
├── pkg/                    # Domain model and shared packages
├── migrations/             # SQL migrations (golang-migrate) and seed SQL
├── configs/                # Asset and relationship type registries, sensor and scan workflow templates
├── deploy/                 # Production compose stack, gateway, Postgres role bootstrap
├── tests/                  # Cross-cutting unit and integration tests
├── tools/                  # Code generators and custom linters
├── scripts/                # Developer and CI scripts
├── changelog.d/            # One changelog entry per change
├── docs/                   # Engineering documentation
├── Dockerfile              # development / builder / production targets
├── Dockerfile.migrations, Dockerfile.seed, Dockerfile.admin-cli
├── docker-compose.yml, docker-compose.dev.yml, docker-compose.prod.yml
├── Makefile                # see docs/MAKEFILE.md
├── .env.example, .air.toml, .golangci.yml
└── go.mod                  # module github.com/openctemio/openctem/api
```

## cmd/

| Command | Purpose |
|---|---|
| `server` | The API server (HTTP, controllers, ingest workers) |
| `bootstrap-admin` | Create the first platform administrator and organization |
| `seed` | Load seed data |
| `rekey` | Re-encrypt stored credentials after rotating `APP_ENCRYPTION_KEY` ([runbook](../deployment/encryption-key-rotation.md)) |
| `encrypt-credentials` | Encrypt credentials stored before encryption was enabled |
| `chainaudit` | Inspect the audit hash chain |
| `refingerprint` | Recompute finding fingerprints after a recipe change |
| `gen-asset-types`, `gen-relationships` | Generate Go and TS code from `configs/*.yaml` |

## internal/

```
internal/
├── app/                    # Application services, one package per bounded context
│   ├── asset/ finding/ scan/ scanrun/ sensor/ scope/ easm/ ingest/ audit/ auth/ tenant/ ...
├── config/                 # Environment configuration (config.go is the source of truth)
├── infra/                  # Adapters
│   ├── http/
│   │   ├── server.go, router.go, chi_router.go   # server and the router abstraction
│   │   ├── routes/         # Route registration by area (assets.go, scanning.go, sensor_v2.go, admin.go, ...)
│   │   │   └── plane/      # The plane table: which authenticator serves which prefix
│   │   ├── handler/        # Request handlers
│   │   ├── middleware/     # Auth, CSRF, rate limits, module gate, data scope, logging, ...
│   │   └── filterquery/    # List query parsing (RFC-048)
│   ├── postgres/           # Repositories (and *_db_test.go against a real database)
│   ├── redis/              # Cache, rate-limit store, metrics
│   ├── controller/         # Background controllers (scheduler, reapers, monitors, retention)
│   ├── notifier/           # Slack, Teams, Telegram, email, webhook, Splunk HEC clients
│   ├── jira/ scm/ fetchers/ importer/ storage/ llm/ websocket/ telemetry/ ...
├── metrics/                # Prometheus metrics
├── adminbootstrap/         # Platform admin bootstrap logic
└── testdb/                 # Safe access to the test database
```

## pkg/

```
pkg/
├── domain/                 # Entities, value objects, repository interfaces (no infra imports)
│   ├── asset/ vulnerability/ (findings) scan/ scanrun/ scanworkflow/ sensor/ scope/ tenant/ ...
│   └── shared/             # IDs and domain errors
├── apierror/               # API error envelope and codes
├── pagination/             # Pagination types
├── sensorproto/            # Sensor protocol v2 wire types
├── sensorkey/              # Sensor key formats (octs_, octe_, rda_)
├── httpsec/                # SSRF-guarded outbound HTTP
├── crypto/ jwt/ oidc/ totp/ password/ validator/ logger/ ...
```

## tests/

```
tests/
├── unit/          # Cross-cutting checks: route authorization coverage, permission catalog
│                  # sync, data-scope classification of every route, ...
└── integration/   # Integration tests against PostgreSQL and Redis
```

Most tests live next to the code they test. See [Testing](../development/testing.md).

## tools/

| Path | Purpose |
|---|---|
| `tools/lint/routestyle` | Route style rules ([API conventions](api-conventions.md)) |
| `tools/lint/openapicontract`, `openapischema` | The spec, the annotations and the registered routes agree |
| `tools/lint/routeperm` | Every route has a permission gate |
| `tools/lint/tenantsql`, `getbyid` | Tenant-scoped SQL ([tenantsql](../../tools/lint/tenantsql/README.md), [getbyid](../../tools/lint/getbyid/README.md)) |
| `tools/lint/sensorvocab` | No "agent" identifiers for sensor concepts |
| `tools/openapidiff` | Contract diff posted on pull requests |
| `tools/gen` | Code generators |

## Layer dependencies

```
cmd/server
    │
    ▼
internal/infra        (HTTP, PostgreSQL, Redis, external clients)
    │
    ▼
internal/app          (application services)
    │
    ▼
pkg/domain            (entities, value objects, interfaces; no infra imports)
```

Dependencies point inward only. See [Clean Architecture](clean-arch.md).
