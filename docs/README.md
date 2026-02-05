# Documentation

## Quick Links

- [Getting Started](getting-started.md) - Start here!
- [Architecture Overview](architecture/overview.md)
- [Development Setup](development/setup.md)

---

## Contents

### Getting Started
- [Getting Started Guide](getting-started.md) - Prerequisites, installation, quick start

### Architecture
- [Overview](architecture/overview.md) - Tech stack, system diagram, design principles
- [Clean Architecture](architecture/clean-arch.md) - Layer details & dependencies
- [Project Structure](architecture/project-structure.md) - Complete file structure
- [Notification System](architecture/notification-system.md) - Real-time alerts, providers, async patterns
- [Scan Orchestration](architecture/scan-orchestration.md) - Pipeline execution, agent coordination
- [Data Sources](architecture/data-sources.md) - Multi-source asset tracking, collectors, scanners
- [Asset Schema](architecture/asset-schema.md) - Standard JSON schema for asset ingestion
- [Asset Properties Schema](asset-properties-schema.md) - JSONB properties schema per asset type
- [Database Notes](architecture/database-notes.md) - Important DB implementation details (finding_count, provider detection)

### Architecture Decision Records (ADR)
- [ADR-001: Use Standard net/http](architecture/decisions/001-use-stdlib-http.md)
- [ADR-002: Multi-Protocol API](architecture/decisions/002-multi-protocol.md)
- [ADR-003: Connector Pattern](architecture/decisions/003-connector-pattern.md)

### API
- [API Reference](api/README.md) - Quick reference
- [Endpoints](api/endpoints.md) - REST API details

### Development
- [Development Setup](development/setup.md) - Full environment setup
- [Coding Style](development/coding-style.md) - Conventions
- [Migrations](development/migrations.md) - Database migrations guide
- [CI/CD](development/ci-cd.md) - GitHub Actions workflows

### Deployment
- [Docker](deployment/docker.md) - Docker & Docker Compose (dev/prod)
- [Kubernetes](deployment/kubernetes.md) - K8s manifests

---

## Project at a Glance

| Component | Technology |
|-----------|------------|
| Language | Go 1.25+ |
| HTTP | Standard `net/http` |
| Database | PostgreSQL 17 |
| Cache | Redis 7 |

## Quick Commands

```bash
# Development (Docker with hot reload)
make docker-dev

# Production
make docker-prod

# Local development
make dev

# Run tests
make test
```
