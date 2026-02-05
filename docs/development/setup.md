# Development Setup

## Prerequisites

- Go 1.25+
- Docker & Docker Compose
- Make (recommended)

## Quick Setup

### Option 1: Docker (Recommended)

```bash
# 1. Clone
git clone https://github.com/exploopio.exploop.git
cd.exploop

# 2. Setup env
cp .env.example .env

# 3. Start development environment with hot reload
# (Migrations run automatically on startup)
make docker-dev
```

### Option 2: Local Development

```bash
# 1. Clone
git clone https://github.com/exploopio.exploop.git
cd.exploop

# 2. Install tools
make install-tools

# 3. Start infrastructure (PostgreSQL, Redis)
docker compose -f docker-compose.yml up -d

# 4. Setup env
cp .env.example .env

# 5. Run migrations
make migrate-up

# 6. Run with hot reload
make dev
```

---

## Development Tools

Install all tools with:

```bash
make install-tools
```

This installs:

| Tool | Purpose |
|------|---------|
| `air` | Hot reload for Go |
| `golangci-lint` | Code linter |
| `migrate` | Database migrations |
| `mockgen` | Mock generator |

---

## Environment Variables

Key variables (see `.env.example` for full list):

```env
# Application
APP_NAME.exploop
APP_ENV=development
APP_DEBUG=true

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER.exploop
DB_PASSWORD=secret
DB_NAME.exploop
DB_SSLMODE=disable

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Logging
LOG_LEVEL=debug
LOG_FORMAT=text
```

---

## Makefile Commands

### Development

```bash
make dev              # Run with hot reload (Air)
make run              # Run without hot reload
make build            # Build binary
make test             # Run all tests
make test-coverage    # Run tests with coverage report
make lint             # Run linter
make fmt              # Format code
make tidy             # Tidy go.mod
```

### Docker

```bash
make docker-dev       # Start dev environment (hot reload)
make docker-dev-d     # Start dev environment (background)
make docker-prod      # Start production environment
make docker-down      # Stop all containers
make docker-logs      # View logs
make docker-logs-app  # View app logs only
make docker-ps        # Show running containers
make docker-clean     # Clean up containers and images
```

### Database

```bash
make migrate-up                    # Apply migrations
make migrate-down                  # Rollback last migration
make migrate-create name=add_users # Create new migration
```

### Code Generation

```bash
make generate         # Generate all (mocks, etc.)
make proto            # Generate protobuf (if using gRPC)
```

---

## Monorepo Structure

This project uses a Go workspace for local development with shared SDK:

```
exploopio/
├── go.work          # Go workspace file
├── api/             # API service (this repo)
├── sdk/             # Shared SDK module
└── agent/           # Agent service
```

### Local Development

`go.work` automatically resolves SDK from local filesystem:

```go
// go.work
go 1.25.0

use (
  ./sdk
  ./api
  ./agent
)
```

### Docker Development

Docker uses `go.work.docker` with adjusted paths:

```go
// api/go.work.docker
use (
  .       // API at /app
  ./sdk   // SDK at /app/sdk
)
```

---

## IDE Setup

### VS Code

Install extensions:
- **Go** (official by Google)
- **Go Test Explorer**
- **Error Lens** (inline error display)

Recommended settings (`.vscode/settings.json`):

```json
{
  "go.formatTool": "goimports",
  "go.lintTool": "golangci-lint",
  "go.lintFlags": ["--fast"],
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": "explicit"
  },
  "[go]": {
    "editor.defaultFormatter": "golang.go"
  }
}
```

### GoLand / IntelliJ

1. Enable **Go Modules integration**
2. Set **Format on Save**:
   - Settings → Tools → Actions on Save
   - Enable "Reformat code" and "Optimize imports"
3. Configure golangci-lint:
   - Settings → Tools → File Watchers → Add golangci-lint

---

## Project Structure

```
exploop/
├── cmd/server/          # Entry point
├── internal/
│   ├── domain/          # Business logic (entities, interfaces)
│   │   ├── shared/      # Shared domain types (ID, errors)
│   │   └── asset/       # Asset bounded context
│   ├── app/             # Application services (use cases)
│   ├── config/          # Configuration loading
│   └── infra/           # Infrastructure adapters
│       ├── http/        # HTTP handlers, router, middleware
│       └── postgres/    # Database repository
├── pkg/                 # Public utilities
│   ├── logger/          # Structured logging
│   ├── pagination/      # Pagination helpers
│   └── apierror/        # API error types
├── migrations/          # SQL migrations
├── tests/               # Integration tests
└── docs/                # Documentation
```

---

## Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific package
go test ./internal/domain/asset/...

# Run with verbose output
go test -v ./...
```

---

## Debugging

### VS Code Launch Configuration

Create `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch Server",
      "type": "go",
      "request": "launch",
      "mode": "auto",
      "program": "${workspaceFolder}/cmd/server",
      "envFile": "${workspaceFolder}/.env"
    }
  ]
}
```

### Delve CLI

```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug
dlv debug ./cmd/server
```

---

## Troubleshooting

### Hot reload not working

Ensure Air is configured with polling (for Docker on macOS/Windows):

```toml
# .air.toml
[build]
  poll = true
  poll_interval = 500
```

### Database connection refused

1. Check if PostgreSQL is running: `docker compose ps`
2. Verify environment variables match docker-compose
3. Try connecting directly: `psql -h localhost -U.exploop -d.exploop`

### Linter errors

Update golangci-lint:
```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```
