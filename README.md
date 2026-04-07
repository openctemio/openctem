# OpenCTEM API

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17-4169E1?logo=postgresql)](https://www.postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis)](https://redis.io)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Backend API for the OpenCTEM Continuous Threat Exposure Management platform. Built with Go, PostgreSQL, and Redis using Clean Architecture (DDD).

## Features

### Asset Management (35 asset types)
- External Attack Surface: Domains, Subdomains, Certificates, IPs
- Applications: Websites, APIs, Mobile Apps, Services
- Cloud: Cloud Accounts, Compute, Storage, Serverless, Container Registry
- Infrastructure: Hosts, Containers, Databases, Networks, VPCs, K8s
- Identity: IAM Users, IAM Roles, Service Accounts
- Code: Git Repositories
- Recon: HTTP Services, Open Ports, Discovered URLs

### Security & Findings
- Vulnerability management with severity-based prioritization
- CVSS scoring and exploit maturity tracking
- Finding lifecycle: Open > Confirmed > Fix Applied > Resolved
- AI-powered triage (Claude, OpenAI, Gemini)
- SLA policy enforcement with escalation

### Scanning
- 30+ scanner integrations via Agent SDK (Nuclei, Trivy, Semgrep, Gitleaks, Nmap, etc.)
- Pipeline-based scan orchestration with multi-step workflows
- Platform agents with K8s-inspired lifecycle management
- Bootstrap token authentication for agent self-registration

### Access Control
- 2-layer RBAC: Permissions (what you can DO) + Groups (what you can SEE)
- 126 granular permissions across all modules
- Real-time permission sync via Redis
- OAuth2 (Google, GitHub, Microsoft) + OIDC (Keycloak)

### Integrations
- ITSM: Jira, Linear, Asana
- SCM: GitHub, GitLab (repository sync, credential import)
- Notifications: Slack, Teams, Telegram, Email, Webhooks
- Compliance: PCI-DSS, HIPAA, SOC2, GDPR, ISO27001, NIST, FedRAMP, CCPA

### Observability
- Prometheus metrics (HTTP, Redis, Pipeline, Scan, Agent, Finding)
- Structured logging (slog)
- Audit logging with tenant isolation

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.26+ |
| Router | Chi (net/http compatible) |
| Database | PostgreSQL 17 |
| Cache/Queue | Redis 7 (Asynq) |
| Auth | JWT (local) / OAuth2 / OIDC |
| Metrics | Prometheus client_golang |
| Encryption | AES-256-GCM |

## Project Structure

```
api/
├── cmd/
│   ├── server/                # Main API server
│   └── openctem-admin/        # Admin CLI tool
├── internal/
│   ├── app/                   # Application services (business logic, 40+ services)
│   ├── config/                # Configuration loading
│   └── infra/                 # Infrastructure adapters
│       ├── http/              # Handlers (200+ endpoints), middleware, routes
│       ├── postgres/          # Repository implementations (30+ repos)
│       ├── redis/             # Cache, sessions, job queue
│       ├── notifier/          # Slack, Teams, Telegram, Email, Webhook
│       ├── llm/               # AI triage (Claude, OpenAI, Gemini)
│       ├── scm/               # GitHub, GitLab integration
│       ├── controller/        # Background jobs
│       └── telemetry/         # Tracing
├── pkg/
│   ├── domain/                # Domain models (35+ entities)
│   │   ├── asset/             # Asset entity, risk scoring, value objects
│   │   ├── vulnerability/     # Finding, approval, suppression
│   │   ├── scan/              # Scan orchestration
│   │   ├── agent/             # Platform agents, bootstrap tokens
│   │   ├── workflow/          # Workflow engine
│   │   ├── pipeline/          # Scan pipelines
│   │   └── ...                # 25+ more domains
│   ├── jwt/                   # Token generation/validation
│   ├── crypto/                # AES-256-GCM encryption
│   ├── validator/             # Input validation + SSRF protection
│   ├── password/              # bcrypt hashing
│   └── pagination/            # Cursor/offset pagination
├── migrations/                # 99 sequential migrations
├── tests/
│   ├── unit/                  # Unit tests (100+ files)
│   ├── integration/           # Integration tests
│   └── repository/            # Repository tests
└── docs/                      # Architecture docs
```

## Quick Start

### Prerequisites

- Go 1.26+
- Docker & Docker Compose
- PostgreSQL 17 (or use Docker)
- Redis 7 (or use Docker)

### Development

```bash
# Start dependencies
docker compose up -d postgres redis

# Run with hot reload
make dev

# Or start everything
docker compose up
```

### Production

```bash
# Set required environment variables
export DB_PASSWORD=<secure-password>
export REDIS_PASSWORD=<secure-password>
export AUTH_JWT_SECRET=<64-char-secret>
export APP_ENCRYPTION_KEY=$(openssl rand -hex 32)
export CORS_ALLOWED_ORIGINS=https://your-domain.com

# Start
docker compose -f docker-compose.prod.yml up -d
```

### Verify

```bash
curl http://localhost:8080/health
# {"status":"healthy"}

curl http://localhost:8080/ready
# {"status":"ready","database":"ok","redis":"ok"}
```

## Environment Variables

### Required (Production)

| Variable | Description |
|----------|-------------|
| `DB_PASSWORD` | PostgreSQL password |
| `REDIS_PASSWORD` | Redis password |
| `AUTH_JWT_SECRET` | JWT signing secret (min 64 chars) |
| `APP_ENCRYPTION_KEY` | AES-256 key (64 hex chars: `openssl rand -hex 32`) |
| `CORS_ALLOWED_ORIGINS` | Allowed CORS origins |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_PROVIDER` | `local` | Auth provider: `local`, `oidc`, `hybrid` |
| `AI_PLATFORM_PROVIDER` | - | AI triage: `claude`, `openai`, `gemini` |
| `SMTP_ENABLED` | `false` | Enable email notifications |
| `RATE_LIMIT_RPS` | `100` | Rate limit (requests/second) |
| `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

## Commands

```bash
make dev             # Run with hot reload (Air)
make build           # Build production binary
make test            # Run all tests
make lint            # Run golangci-lint (30 linters)
make fmt             # Format code (goimports)
make migrate-up      # Run database migrations
make migrate-down    # Rollback last migration
make security-scan   # Run security scan (semgrep + gitleaks + trivy)
```

## API Endpoints (200+)

### Core

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Liveness check |
| GET | `/ready` | Readiness check (DB + Redis) |
| GET | `/metrics` | Prometheus metrics |
| GET | `/docs` | API documentation |

### Assets

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/assets` | List assets (paginated, 10+ filters) |
| POST | `/api/v1/assets` | Create asset |
| GET | `/api/v1/assets/{id}` | Get asset (tenant-scoped) |
| PUT | `/api/v1/assets/{id}` | Update asset |
| DELETE | `/api/v1/assets/{id}` | Delete asset |
| GET | `/api/v1/assets/stats` | Aggregated statistics (SQL) |
| POST | `/api/v1/assets/bulk/status` | Atomic bulk status update |
| POST | `/api/v1/assets/{id}/scan` | Trigger scan |

### Findings, Scans, Integrations, Compliance, Pentest, Workflows...

See `/docs` endpoint for complete OpenAPI documentation.

### Platform Agents

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/platform/register` | Agent self-registration |
| PUT | `/api/v1/platform/lease` | Renew agent lease |
| POST | `/api/v1/platform/poll` | Long-poll for jobs |
| POST | `/api/v1/platform/jobs/{id}/result` | Submit job results |

## Security

- SSRF protection on all URL inputs (webhooks, integrations, template sources)
- OAuth redirect URI whitelist validation
- Command injection prevention in scan executors (ExtraArgs validation)
- Tenant isolation on all 200+ endpoints (WHERE tenant_id = ?)
- Password reset token single-use enforcement
- X-Forwarded header injection prevention
- AES-256-GCM credential encryption
- bcrypt password hashing (cost=12)
- Constant-time token comparison
- Rate limiting on all endpoints

## License

MIT License - See [LICENSE](LICENSE) file for details.
