# Docker Deployment

## Overview

OpenCTEM uses a **single Dockerfile with multiple build targets**:

```
Dockerfile
├── base        # Shared: Go 1.25, dependencies
├── development # Dev: Air (hot reload), Delve (debugger)
├── builder     # Build: Compile binary
└── production  # Prod: Minimal Alpine image
```

### Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-target build (dev, prod) |
| `docker-compose.yml` | Base services (PostgreSQL, Redis) |
| `docker-compose.dev.yml` | Development app (target: development) |
| `docker-compose.prod.yml` | Production app (target: production) |

---

## Quick Start

### Development (Hot Reload)

```bash
make docker-dev

# Or directly
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Features:
- Hot reload with Air
- **Auto-migration on startup**
- Delve debugger on port 2345
- Source code mounted as volume
- SDK module mounted (local development)
- Debug logging (text format)

### Production

```bash
# Set required environment variables
export DB_PASSWORD=your_secure_password
export REDIS_PASSWORD=your_redis_password
export KEYCLOAK_BASE_URL=https://keycloak.example.com
export KEYCLOAK_REALM=openctem
export CORS_ALLOWED_ORIGINS=https://app.example.com

make docker-prod

# Or directly
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Features:
- Optimized multi-stage build (~15MB image)
- Non-root user
- JSON logging
- Resource limits (CPU/Memory)
- Health checks
- Auto-restart

---

## Dockerfile Structure

```dockerfile
# =============================================================================
# Base stage (shared)
# =============================================================================
FROM golang:1.25-alpine AS base
WORKDIR /app
RUN apk add --no-cache git ca-certificates tzdata
COPY go.mod go.sum ./
RUN go mod download

# =============================================================================
# Development stage
# =============================================================================
FROM base AS development
RUN go install github.com/air-verse/air@latest
RUN go install github.com/go-delve/delve/cmd/dlv@latest
EXPOSE 8080 9090 2345
CMD ["air", "-c", ".air.toml"]

# =============================================================================
# Builder stage
# =============================================================================
FROM base AS builder
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/bin/server ./cmd/server

# =============================================================================
# Production stage
# =============================================================================
FROM alpine:3.20 AS production
WORKDIR /app
RUN addgroup -g 1000 -S openctem && adduser -u 1000 -S openctem -G openctem
COPY --from=builder /app/bin/server .
USER openctem
EXPOSE 8080 9090
HEALTHCHECK CMD wget --spider http://localhost:8080/health || exit 1
ENTRYPOINT ["./server"]
```

---

## SDK Module Setup

The API depends on the SDK module (`github.com/openctemio/sdk-go`).

### Development (Local SDK)

In development, SDK is mounted as a volume and resolved via `go.work.docker`:

```yaml
# docker-compose.dev.yml
volumes:
  - ../sdk:/app/sdk              # Mount SDK source
  - ./go.work.docker:/app/go.work  # Go workspace for local resolution
```

```go
// go.work.docker (for Docker container)
go 1.25.0

use (
  .       // API (mounted at /app)
  ./sdk   // SDK (mounted at /app/sdk)
)
```

### Production (GitHub Module)

In production, SDK is fetched from GitHub as a released module:

```go
// go.mod
require github.com/openctemio/sdk-go v0.1.0
```

> **Note**: SDK must be released on GitHub with proper version tag (e.g., `v0.1.0`) before production builds work.

---

## Auto-Migration (Development)

Development containers automatically run database migrations on startup.

### How It Works

```
1. Wait for database to be ready (max 30s)
2. Run: migrate -path /app/migrations up
3. Start Air for hot reload
```

### Entrypoint Script

```bash
# scripts/dev-entrypoint.sh
=== Development Entrypoint ===
Waiting for database...
Database is ready!
Running database migrations...
no change
Migrations complete!
Starting development server with Air...
```

### Disable Auto-Migration

```yaml
# docker-compose.dev.yml
services:
  app:
    environment:
      AUTO_MIGRATE: "false"   # Skip migrations on startup
```

### Manual Migration

```bash
# Inside container
migrate -path /app/migrations -database "$DB_URL" up

# From host (using Make)
make docker-migrate-up
make docker-migrate-down
make docker-migrate-version
```

---

## Build Commands

```bash
# Build specific target
docker build --target development -t openctem:dev .
docker build --target production -t openctem:latest .

# Using Makefile
make docker-build       # Production image
make docker-build-dev   # Development image
```

---

## Docker Compose Usage

### Development

```yaml
# docker-compose.dev.yml
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
      target: development    # <-- Use development stage
    volumes:
      - .:/app               # Mount source for hot reload
    ports:
      - "8080:8080"
      - "2345:2345"          # Delve debugger
```

### Production

```yaml
# docker-compose.prod.yml
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
      target: production     # <-- Use production stage
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 512M
```

---

## Make Commands

```bash
# Development
make docker-dev          # Start with hot reload (foreground)
make docker-dev-d        # Start in background

# Production
make docker-prod         # Start production

# Build
make docker-build        # Build production image
make docker-build-dev    # Build development image

# Management
make docker-down         # Stop all containers
make docker-logs         # View all logs
make docker-logs-app     # View app logs only
make docker-ps           # Show running containers
make docker-clean        # Remove containers, volumes, images
```

---

## Environment Variables

### Development (auto-set)

```env
APP_ENV=development
LOG_LEVEL=debug
LOG_FORMAT=text
```

### Production (required)

```bash
# Database
export DB_PASSWORD=secure_password
export DB_SSLMODE=require

# Redis
export REDIS_PASSWORD=redis_password

# Keycloak Authentication (external)
export KEYCLOAK_BASE_URL=https://keycloak.example.com
export KEYCLOAK_REALM=openctem
export KEYCLOAK_CLIENT_ID=api  # Optional

# CORS
export CORS_ALLOWED_ORIGINS=https://app.example.com

# Optional
export DB_USER=openctem
export SERVER_REQUEST_TIMEOUT=30s
```

---

## Debugging with Delve

Development image includes Delve debugger:

```bash
# Start with debug mode
docker compose -f docker-compose.yml -f docker-compose.dev.yml up

# Connect VS Code to port 2345
# Or use: dlv connect localhost:2345
```

VS Code `launch.json`:
```json
{
  "name": "Docker: Attach",
  "type": "go",
  "request": "attach",
  "mode": "remote",
  "port": 2345,
  "host": "127.0.0.1"
}
```

---

## Health Checks

```bash
# App
curl http://localhost:8080/health

# PostgreSQL (use docker compose exec with service name)
docker compose exec postgres pg_isready -U openctem

# Redis (use docker compose exec with service name)
docker compose exec redis redis-cli ping
```

---

## Troubleshooting

### Hot reload not working

Check `.air.toml` has polling enabled:
```toml
[build]
  poll = true
  poll_interval = 500
```

### Build cache issues

```bash
# Rebuild without cache
docker compose -f docker-compose.yml -f docker-compose.dev.yml build --no-cache
```

### Image size

```bash
# Check image sizes
docker images openctem

# Production should be ~15-20MB
# Development will be larger (~500MB+)
```

---

## Future: Kubernetes & Helm

The `deploy/` folder is reserved for additional deployment configurations:

```
deploy/
├── kubernetes/          # K8s manifests (Deployment, Service, Ingress)
├── helm/               # Helm charts
└── terraform/          # Infrastructure as code
```

Docker files (Dockerfile, docker-compose*.yml) remain in the project root for simplicity and convention.
