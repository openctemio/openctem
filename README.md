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
| `AUTH_ALLOW_REGISTRATION` | `true` | Allow public registration. **Set `false` in production** — use invitation flow instead |
| `AI_PLATFORM_PROVIDER` | — | AI triage: `claude`, `openai`, `gemini` |
| `SMTP_ENABLED` | `false` | Enable email notifications (required for invitations) |
| `RATE_LIMIT_RPS` | `100` | Rate limit (requests/second) |
| `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

### Production User Management

In production, disable public registration and use the invitation system:

```env
AUTH_ALLOW_REGISTRATION=false   # No public signup
SMTP_ENABLED=true               # Required for invitation emails
```

**Flow**: Admin creates invitation → User receives email → User clicks link → Account created → User joins tenant.

```bash
# API: Create invitation (requires team:admin permission)
POST /api/v1/tenants/{tenant}/invitations
{"email": "user@company.com", "role_ids": ["00000000-0000-0000-0000-000000000003"]}

# System roles (pre-seeded, shared across all tenants):
#   00000000-...-000000000001  owner       (full access)
#   00000000-...-000000000002  admin       (all except team:delete)
#   00000000-...-000000000003  member      (read/write, no delete)
#   00000000-...-000000000004  viewer      (read-only)

# User accepts invitation via token link
POST /api/v1/invitations/{token}/accept
```

### Per-Tenant SMTP

Each tenant can configure its own SMTP server for outgoing emails (invitations, notifications).
If not configured, the system-wide SMTP (`SMTP_HOST`, etc.) is used as fallback.

**Setup via email integration:**
```bash
POST /api/v1/integrations
{
  "name": "Company Email",
  "category": "notification",
  "provider": "email",
  "auth_type": "basic",
  "metadata": {
    "smtp_host": "smtp.company.com",
    "smtp_port": 587,
    "smtp_user": "noreply@company.com",
    "smtp_password": "app-password",
    "smtp_from": "noreply@company.com",
    "smtp_from_name": "Security Team",
    "smtp_tls": true
  }
}
```

**Resolution order:**
1. Tenant has active email integration → use tenant SMTP
2. No tenant integration → use system SMTP (`SMTP_HOST`, `SMTP_PORT`, etc.)
3. No system SMTP → emails skipped (logged as warning)

Credentials are encrypted at rest using AES-256-GCM.

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

## Deployment

### Docker Compose

```bash
# 1. Go to setup directory
cd ../setup

# 2. Initialize environment files
make init-prod

# 3. Generate secrets and update .env files
make generate-secrets
# Update all <CHANGE_ME> values in .env.*.prod files

# 4. Setup SSL (self-signed or Let's Encrypt)
make auto-ssl

# 5. Start production
make prod-up

# 6. Create first admin user
make bootstrap-admin-prod email=admin@example.com
```

### Kubernetes (Helm)

```bash
# 1. Create namespace and secrets
kubectl create namespace openctem

kubectl create secret generic openctem-api-secrets \
  --namespace openctem \
  --from-literal=AUTH_JWT_SECRET=$(openssl rand -base64 48) \
  --from-literal=APP_ENCRYPTION_KEY=$(openssl rand -hex 32) \
  --from-literal=DB_USER=openctem \
  --from-literal=DB_PASSWORD=$(openssl rand -hex 24) \
  --from-literal=DB_NAME=openctem

kubectl create secret generic openctem-db-secrets \
  --namespace openctem \
  --from-literal=username=openctem \
  --from-literal=password=<same-db-password>

kubectl create secret generic openctem-redis-secrets \
  --namespace openctem \
  --from-literal=password=$(openssl rand -hex 24)

# 2. Install with bootstrap admin (first-time only)
helm install openctem ../setup/kubernetes/helm/openctem \
  --namespace openctem \
  --set bootstrapAdmin.enabled=true \
  --set bootstrapAdmin.email=admin@example.com \
  --set ingress.hosts[0].host=openctem.yourdomain.com

# 3. Get the admin API key (shown once — save it!)
kubectl logs job/openctem-bootstrap-admin -n openctem
```

### Bootstrap Admin (First-time Setup)

The first admin user must be created via CLI — there is no default account.

**Docker Compose:**
```bash
make bootstrap-admin-prod email=admin@example.com role=super_admin
```

**Kubernetes (during helm install):**
```bash
helm install openctem ./openctem \
  --set bootstrapAdmin.enabled=true \
  --set bootstrapAdmin.email=admin@example.com
```

**Kubernetes (after install):**
```bash
kubectl exec -it deploy/openctem-api -n openctem -- \
  /app/bootstrap-admin -email=admin@example.com
```

**Standalone binary:**
```bash
./bootstrap-admin \
  -db="postgres://user:pass@host:5432/openctem?sslmode=require" \
  -email=admin@example.com \
  -role=super_admin
```

| Flag | Env Var | Description |
|------|---------|-------------|
| `-db` | `DATABASE_URL` or `DB_HOST`/`DB_USER`/`DB_PASSWORD`/`DB_NAME` | Database connection |
| `-email` | `ADMIN_EMAIL` | Admin email (required) |
| `-name` | `ADMIN_NAME` | Display name (defaults to email prefix) |
| `-role` | — | `super_admin`, `ops_admin`, `viewer` |
| `-api-key` | `BOOTSTRAP_ADMIN_KEY` | Use specific key (auto-generated if empty) |
| `-force` | — | Overwrite existing admin with same email |

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

## Legal

- [Terms of Service](../docs/legal/terms-of-service.md)
- [Privacy Policy](../docs/legal/privacy-policy.md)
