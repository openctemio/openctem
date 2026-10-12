# Getting Started (development)

This page gets the API running on a developer machine. To install OpenCTEM for
real use, follow the operator documentation at
[docs.openctem.io/install](https://docs.openctem.io/install/).

## Prerequisites

- Go 1.26+
- Node.js (for the web console and the generated contract types)
- Docker with Docker Compose
- Make

The API is the `api/` directory of the
[`openctemio/openctem`](https://github.com/openctemio/openctem) monorepo; the web
console is `web/`. From the repository root, `make setup` downloads the Go and npm
dependencies, enables the git hooks and generates the contract files.

```bash
git clone https://github.com/openctemio/openctem.git
cd openctem
make setup
```

## Run the API in Docker (recommended)

```bash
cd api
cp .env.example .env
make docker-dev
```

This starts PostgreSQL 17, Redis 7 and the API (`target: development` of the
`Dockerfile`). The API container applies migrations on start, then runs with hot
reload (Air); Delve listens on port 2345.

Check it:

```bash
curl http://localhost:8080/health
# {"status":"healthy","timestamp":"..."}
```

Create the first platform administrator and organization with the
`bootstrap-admin` command (flags: `-email`, `-org-name`, `-org-owner-email`; run
`go run ./cmd/bootstrap-admin -h` for the full list). See
[Migrations](development/migrations.md) for seeding details.

Run the web console against it from the repository root with `make dev-web`
(http://localhost:3000).

## Run the API without Docker

```bash
cd api
make install-tools               # golangci-lint, staticcheck, air, migrate, mockgen
docker compose -f docker-compose.yml up -d   # only PostgreSQL and Redis
make migrate-up
make dev                         # hot reload (falls back to `make run` without air)
```

## Configuration

All settings are environment variables; `api/.env.example` lists them with
comments, and `api/internal/config/config.go` is the source of truth. The ones you
need locally:

```env
APP_ENV=development              # required locally: unset means production
SERVER_PORT=8080
DB_HOST=localhost
DB_USER=openctem
DB_PASSWORD=secret
DB_NAME=openctem
REDIS_HOST=localhost
LOG_LEVEL=debug                  # debug | info | warn | error
LOG_FORMAT=text                  # text | json
AUTH_PROVIDER=local              # local (built-in accounts) | oidc | hybrid
AUTH_JWT_SECRET=...               # the .env.example value works in development
APP_ENCRYPTION_KEY=...            # same; generate real ones for anything else
```

The development values in `.env.example` are refused whenever `APP_ENV` is not
`development`, and a secret still holding example text (`openssl rand -hex 32`,
`<CHANGE_ME...>`) is refused in every mode. To validate the settings without
starting or connecting to anything (the server reads the environment, not the
`.env` file):

```bash
(set -a; . ./.env; set +a; GOWORK=off go run ./cmd/server -check-config)
```

Operator-facing configuration (TLS, SSO, SMTP, scaling) is documented at
[docs.openctem.io/configuration](https://docs.openctem.io/configuration/).

## Project layout

```
api/
├── cmd/server/          # API entry point (also bootstrap-admin, rekey, seed, ... in cmd/)
├── internal/
│   ├── app/             # Application services, one package per bounded context
│   ├── config/          # Environment configuration
│   └── infra/           # Adapters: http (handlers, routes, middleware), postgres, redis, ...
├── pkg/
│   ├── domain/          # Entities, value objects, repository interfaces (no external deps)
│   └── ...              # Shared packages (logger, apierror, pagination, ...)
├── migrations/          # SQL migrations (golang-migrate)
└── tests/               # Integration and end-to-end tests
```

See [Project Structure](architecture/project-structure.md) for the full layout.

## Common commands

```bash
make dev               # run with hot reload
make test              # unit tests (DB-backed tests need TEST_DATABASE_URL, or use make test-db)
make lint              # golangci-lint
make fmt               # format code

make docker-dev        # development stack in Docker
make docker-down       # stop the containers
make docker-logs       # follow the logs

make migrate-up        # apply migrations
make migrate-down      # roll back the last migration
make migrate-create name=add_widgets   # new migration pair
```

All targets: [Makefile reference](MAKEFILE.md).

## Next steps

- [Architecture overview](architecture/overview.md)
- [Development setup](development/setup.md) (IDE, debugging, tooling)
- [API reference](api/README.md)
