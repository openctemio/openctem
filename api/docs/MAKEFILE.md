# Makefile Commands Guide

The targets of `api/Makefile` (run them in `api/`). The repository root `Makefile`
has thin targets for both components (`make setup`, `make generate`, `make check`,
`make dev-api`, `make dev-web`, `make api-<target>`); run `make help` there.

## Quick Start

```bash
# Show all available commands
make help

# Install development tools
make install-tools

# Run development server with hot reload
make dev
```

## Development Commands

### Building & Running

| Command | Description |
|---------|-------------|
| `make build` | Build the binary |
| `make run` | Run the application directly |
| `make dev` | Run with hot reload (requires air) |
| `make clean` | Clean build artifacts |

### Code Quality

| Command | Description |
|---------|-------------|
| `make lint` | Run golangci-lint (pinned version) over the whole tree |
| `make lint-new` | golangci-lint on code this branch adds (`BASE_REF`, default `origin/develop`) |
| `make lint-ci` | Exactly what the CI Lint job gates on (go vet + staticcheck + `lint-new`) |
| `make fmt` | Format code with gofmt |
| `make tidy` | Tidy Go dependencies |
| `make test` | Run all tests (DB-backed tests skip unless `TEST_DATABASE_URL` names a `*_test` database) |
| `make test-db` | Run all tests against `TEST_DATABASE_URL`; a missing or unreachable database fails instead of skipping |
| `make test-coverage` | Run tests with coverage report |
| `make test-load`, `make test-load-bench` | Load tests and benchmarks for the platform queue |

### Documentation

| Command | Description |
|---------|-------------|
| `make swagger` | Generate the OpenAPI spec (not committed) |
| `make contract` | Generate the spec, the route manifest and the web route permission map |
| `make swagger-check` | Generate the spec, then fail if the annotations, the spec and the routes disagree |
| `make swagger-install` | Install the pinned swag CLI |

### Code generation

| Command | Description |
|---------|-------------|
| `make generate` | `go generate ./...` (mocks) |
| `make generate-relationships` | Regenerate relationship types (Go + TS) from `configs/relationship-types.yaml` |
| `make generate-asset-types` | Regenerate the asset type registry (Go + TS) from `configs/asset-types.yaml` |
| `make asset-types-sql` | Print the SQL block that seeds `asset_types` (the body of a registry migration) |
| `make asset-types-check` | Fail if the YAML, the generated files and the newest registry migration disagree |

## Docker Commands

### Development

| Command | Description |
|---------|-------------|
| `make docker-dev` | Start development environment |
| `make docker-dev-d` | Start development in background |
| `make docker-down` | Stop all services |
| `make docker-logs` | View logs |
| `make docker-logs-app` | View only app logs |
| `make docker-ps` | Show running containers |

### Production

| Command | Description |
|---------|-------------|
| `make docker-build` | Build production image |
| `make docker-build-dev` | Build development image |
| `make docker-prod` | Print how to start the production stack (`api/deploy`) |
| `make docker-clean` | Remove containers, volumes, images |

## Database Commands

### Migrations

| Command | Description |
|---------|-------------|
| `make migrate-up` | Run migrations (local) |
| `make migrate-down` | Rollback last migration (local) |
| `make migrate-create name=<name>` | Create new migration |
| `make migrate-status` | Show migration status |
| `make docker-migrate-up` | Run migrations in Docker |
| `make docker-migrate-down` | Rollback in Docker |
| `make docker-migrate-version` | Show migration version |
| `make docker-migrate-force version=<n>` | Force the recorded migration version (dirty-migration recovery only) |

### Database Setup

| Command | Description |
|---------|-------------|
| `make db-setup` | Setup database (schema + required data) |
| `make db-setup-dev` | Setup with test data |
| `make db-fresh` | Reset and setup from scratch |
| `make docker-reset-db` | Reset database |
| `make docker-psql` | Open psql shell in Docker |

### Seeding

| Command | Description |
|---------|-------------|
| `make seed-required` | Seed required data (local) |
| `make docker-seed-required` | Seed required data (docker) |
| `make docker-seed` | Development seed (required data; users and organizations come from `bootstrap-admin`) |

## Security & Pre-commit

### Installation

Commit-time git hooks are the repository's `.githooks/` (shared by `api/` and
`web/`). Enable them once, from the repository root:

```bash
make hooks        # git config core.hooksPath .githooks (make setup does this too)
```

`.githooks/pre-commit` runs `gofmt -l` on staged Go files (and type-check +
lint-staged for staged `web/` files); `.githooks/commit-msg` rejects AI
attribution lines.

The heavier security hooks in `api/.pre-commit-config.yaml` are run **on demand**,
not on every commit. To install their tools:

```bash
make pre-commit-install   # in api/
```

This installs (if missing) `pip` (Ubuntu/Debian), `pre-commit`, Go, `betterleaks`,
`trivy` and `hadolint`, then enables `.githooks`. It does **not** run
`pre-commit install`: that command refuses to work while `core.hooksPath` is set.

### Usage

| Command | Description |
|---------|-------------|
| `make pre-commit-run` | Run all hooks in `api/.pre-commit-config.yaml` on all files |
| `make pre-commit-update` | Update hooks to latest versions |
| `make security-scan` | Full security scan (betterleaks + gosec + trivy) |
| `make secrets` | Run betterleaks only |

## Plans and releases

| Command | Description |
|---------|-------------|
| `make assign-plan tenant=<uuid> plan=<plan>` | Assign a plan to an organization |
| `make list-tenants` | List organizations with their plans |
| `make list-plans` | List the available plans |
| `make release-branch VERSION=vX.Y.Z` | Build a release branch that merges cleanly into `main` (add `PUSH=--push`) |

## Tool Installation

```bash
# Install all development tools
make install-tools
```

Installs:
- golangci-lint (pinned version)
- staticcheck
- air (hot reload)
- migrate (database migrations)
- mockgen (mock generation)

## Common Workflows

### First-time Setup

```bash
# 1. Install tools
make install-tools

# 2. Enable the git hooks (from the repository root)
make -C .. hooks

# 3. Setup database
make db-setup-dev

# 4. Run development server
make dev
```

### Daily Development

```bash
# Start development
make dev

# Run tests
make test

# Check code quality
make lint
make test
```

### Before Committing

```bash
# Format code
make fmt

# Run all checks
make lint
make test

# The .githooks pre-commit hook runs gofmt on staged files at git commit
```

### Docker Development

```bash
# Start services
make docker-dev

# View logs
make docker-logs-app

# Stop services
make docker-down
```

## Environment Variables

Database configuration is loaded from `.env` file:
- `DB_HOST` - Database host (default: localhost)
- `DB_PORT` - Database port (default: 5432)
- `DB_USER` - Database user
- `DB_PASSWORD` - Database password
- `DB_NAME` - Database name (default: openctem)

## Troubleshooting

### Pre-commit installation fails

If `make pre-commit-install` fails while installing tools:
1. Ensure you're on a supported platform (Ubuntu/Debian or macOS)
2. On Ubuntu, the Makefile will auto-install pip
3. On macOS, ensure Homebrew is installed

### Migration errors

```bash
# Check migration status
make migrate-status

# Force migration to specific version
make docker-migrate-force version=X
```

### Docker issues

```bash
# Clean everything and restart
make docker-clean
make docker-dev
```
