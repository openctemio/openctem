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
- [Scan Coverage (Tenable)](architecture/scan-coverage.md) - License-aware rolling coverage, Nessus Pro + Tenable.sc, .nessus→CTIS converter
- [Shift-Left CI Scanning](architecture/shift-left-ci-scanning.md) - Agent-first SAST/SCA/secrets in CI: structure + dataflow diagrams, branch-aware findings, risk-aware gate, PR decoration (RFC-008)
- [Ticketing Integration (Jira)](architecture/ticketing-integration.md) - Per-tenant client resolver, create/link/webhook, Mobilization
- [Tenable — User & Data Flow](architecture/tenable-user-and-data-flow.md) - How operators interact with Tenable on the UI + end-to-end data flow (agent/direct/upload)
- [Data Sources](architecture/data-sources.md) - Multi-source asset tracking, collectors, scanners
- [Asset Schema](architecture/asset-schema.md) - Standard JSON schema for asset ingestion
- [Asset Properties Schema](asset-properties-schema.md) - JSONB properties schema per asset type
- [Database Notes](architecture/database-notes.md) - Important DB implementation details (finding_count, provider detection)
- [SSO Authentication](architecture/sso-authentication.md) - Per-tenant + env-fallback Entra/OIDC design, id_token verification, nOAuth/`xms_edov`, PKCE, verified-domain JIT gate (see also the operator [how-to](how-to/configure-entraid.md))
- [Multi-Tenant EntraID Model](architecture/multi-tenant-entraid-model.md) - "One platform, many tenants — each brings its own EntraID": per-tenant Azure apps, `?org=` login routing, and the `tid`-pin isolation wall (conceptual model)

### Architecture Decision Records (ADR)
- [ADR-001: Use Standard net/http](architecture/decisions/001-use-stdlib-http.md)
- [ADR-002: Multi-Protocol API](architecture/decisions/002-multi-protocol.md)
- [ADR-003: Connector Pattern](architecture/decisions/003-connector-pattern.md)

### API
- [API Reference](api/README.md) - Quick reference
- [Endpoints](api/endpoints.md) - REST API details

### How-To (Operator Guides)
- [Configure Microsoft Entra ID (Azure AD) SSO](how-to/configure-entraid.md) - Both Microsoft login paths, Azure app registration, env vars/admin UI, `xms_edov` claim, verified domains, redirect allow-list, troubleshooting (incl. the login-button 404)

### Development
- [Development Setup](development/setup.md) - Full environment setup
- [Coding Style](development/coding-style.md) - Conventions
- [Migrations](development/migrations.md) - Database migrations guide
- [CI/CD](development/ci-cd.md) - GitHub Actions workflows

### Competitive analysis
- [OASM vs OpenCTEM](competitive/oasm-comparison.md) - Source-level comparison against oasm-platform/open-asm: what we have, what we lack, what is built-but-unwired, and the phased adoption plan with a tracking table

### Deployment
- [Safe Deploy & Migrations](deployment/safe-deploy-and-migrations.md) - Canonical safe-deploy sequence, expand-contract rules, schema-check semantics, dirty-migration recovery, rollback
- [Docker](deployment/docker.md) - Docker & Docker Compose (dev/prod)
- [Kubernetes](deployment/kubernetes.md) - K8s manifests

---

## Project at a Glance

| Component | Technology |
|-----------|------------|
| Language | Go 1.26+ |
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
