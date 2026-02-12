# Getting Started

## Prerequisites

- Go 1.25+
- Docker & Docker Compose
- Make (optional but recommended)

## Quick Start with Docker (Recommended)

### 1. Clone Repository

```bash
git clone https://github.com/openctemio/openctem.git
cd openctem
```

### 2. Setup Environment

```bash
cp .env.example .env
```

### 3. Start Development Environment

```bash
# With hot reload
make docker-dev
```

This starts:
- **App** with hot reload (Air)
- **PostgreSQL 17**
- **Redis 7**

### 4. Verify Installation

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{"status":"healthy","timestamp":"2025-01-01T00:00:00Z"}
```

---

## Local Development (Without Docker)

### 1. Install Dependencies

```bash
go mod download
```

### 2. Install Development Tools

```bash
make install-tools
```

This installs:
- `golangci-lint` - Linter
- `air` - Hot reload
- `migrate` - Database migrations
- `mockgen` - Mock generator

### 3. Start Infrastructure

```bash
# Start only PostgreSQL and Redis
docker compose -f docker-compose.yml up -d
```

### 4. Run Migrations

```bash
make migrate-up
```

### 5. Run Application

```bash
# With hot reload
make dev

# Without hot reload
make run
```

---

## Environment Variables

Key environment variables (see `.env.example` for full list):

```env
# Application
APP_NAME=openctem
APP_ENV=development          # development | production

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=openctem
DB_PASSWORD=secret
DB_NAME=openctem
DB_SSLMODE=disable

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Logging
LOG_LEVEL=debug              # debug | info | warn | error
LOG_FORMAT=text              # text | json

# Keycloak Authentication
KEYCLOAK_BASE_URL=http://localhost:8080
KEYCLOAK_REALM=openctem
KEYCLOAK_CLIENT_ID=api

# CORS
CORS_ALLOWED_ORIGINS=*       # Use specific origins in production
```

---

## Project Structure Overview

```
openctem/
├── cmd/server/main.go       # Entry point
├── internal/
│   ├── domain/              # Business logic (no external deps)
│   │   ├── asset/           # Asset entity, value objects, repository interface
│   │   └── shared/          # Shared types (ID, errors)
│   ├── app/                 # Application services
│   └── infra/               # External adapters
│       ├── http/            # HTTP handlers, router, middleware
│       └── postgres/        # Database implementation
├── pkg/                     # Reusable utilities
├── migrations/              # SQL migrations
└── tests/                   # Integration tests
```

---

## Common Commands

```bash
# Development
make dev              # Run with hot reload
make run              # Run without hot reload
make test             # Run tests
make lint             # Run linter
make fmt              # Format code

# Docker
make docker-dev       # Start dev environment
make docker-prod      # Start prod environment
make docker-down      # Stop containers
make docker-logs      # View logs

# Database
make migrate-up       # Apply migrations
make migrate-down     # Rollback last migration
make migrate-create name=add_users  # Create new migration
```

---

## Next Steps

- Read [Architecture Overview](architecture/overview.md)
- Explore [API Reference](api/)
- Setup [IDE](development/setup.md)
