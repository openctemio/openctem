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
- 30+ scanner integrations via Agent SDK (Nuclei, Trivy, Semgrep, Betterleaks, Nmap, etc.)
- Pipeline-based scan orchestration with multi-step workflows
- Platform agents with K8s-inspired lifecycle management
- Bootstrap token authentication for agent self-registration

### Access Control
- 2-layer RBAC: Permissions (what you can DO) + Groups (what you can SEE)
- 164 granular permissions across all modules
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
│   └── bootstrap-admin/       # Creates the first platform administrator
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
├── migrations/                # 156 sequential migrations
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

The production stack exposes ONE port: a gateway on 443 (HTTPS) fronts both
the web UI and this API, like any appliance. The API, the web UI, Postgres and
Redis are never published.

```bash
cd deploy
cp .env.example .env   # set OPENCTEM_HOSTNAME, OPENCTEM_PUBLIC_URL, OPENCTEM_TLS_MODE, secrets
docker compose up -d
```

TLS modes (`OPENCTEM_TLS_MODE`): `internal` (own CA, for LAN/IP installs; the
root for sensors is exported to `deploy/ca/`), `acme` (Let's Encrypt), `files`
(your certificate), `http` (only behind your own TLS proxy, explicit opt-in).
Routing table and details: `deploy/gateway/Caddyfile` and the docs page
"Exposing OpenCTEM: one HTTPS port". Sensors use `API_URL=https://<host>`.

### Verify

```bash
curl --cacert deploy/ca/openctem-root-ca.crt https://<host>/health
# {"status":"healthy"}

# Readiness and metrics are not public; ask from inside the network:
docker compose -f deploy/docker-compose.yml exec api wget -qO- localhost:8080/ready
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
make security-scan   # Run security scan (semgrep + betterleaks + trivy)
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

# 6. Create the first admin and its break-glass backup (see Bootstrap Admin below)
docker compose exec api /app/bootstrap-admin -email=admin@example.com -backup-email=breakglass@example.com
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
  --set bootstrapAdmin.backupEmail=breakglass@example.com \
  --set ingress.hosts[0].host=openctem.yourdomain.com

# 3. Get the administrator's temporary password (shown once), then sign in on
#    /login and set up two-step verification when you open the admin console
kubectl logs job/openctem-bootstrap-admin -n openctem
```

### Bootstrap Admin (First-time Setup)

The first platform administrators must be created with `bootstrap-admin` —
there is no default account. One run creates two (RFC-022 revision 4):

- the **primary** administrator (`-email`, role `-role`, default `super_admin`);
- a **break-glass backup** (`-backup-email`), always a `super_admin`. It is a
  local account that can never be bound to the platform identity provider and
  is exempt from "require IdP", so the console stays reachable when the IdP is
  down. Every sign-in with it writes a high-severity `console.break_glass_sign_in`
  audit row, a `WARN` log line with `alert=break_glass_sign_in` (alert on it), and
  emails the other administrators through the system SMTP sender (`SMTP_*`).
  Test it periodically (at least every 90 days): sign in with it, then another
  super admin confirms the test on the console's Administrators page. Store its
  credentials offline.

Each gets a new sign-in account (an email that already has one is refused) and a
temporary password printed **once**. On first use the administrator signs in on
`/login`, enrolls an authenticator app when opening the admin console, and must
change the temporary password before anything else. Administrators have no API
keys. The run is idempotent: existing administrators are reported and left
alone, so re-running with `-backup-email` adds a backup to an existing install.
`-backup-email` is required unless `-no-backup` is passed explicitly.

**Docker Compose:**
```bash
docker compose exec api /app/bootstrap-admin \
  -email=admin@example.com -backup-email=breakglass@example.com
```

**Kubernetes (during helm install):**
```bash
helm install openctem ./openctem \
  --set bootstrapAdmin.enabled=true \
  --set bootstrapAdmin.email=admin@example.com \
  --set bootstrapAdmin.backupEmail=breakglass@example.com
```

**Kubernetes (after install):**
```bash
kubectl exec -it deploy/openctem-api -n openctem -- \
  /app/bootstrap-admin -email=admin@example.com -backup-email=breakglass@example.com
```

**Standalone binary:**
```bash
./bootstrap-admin \
  -db="postgres://user:pass@host:5432/openctem?sslmode=require" \
  -email=admin@example.com \
  -backup-email=breakglass@example.com
```

| Flag | Env Var | Description |
|------|---------|-------------|
| `-db` | `DATABASE_URL` or `DB_HOST`/`DB_USER`/`DB_PASSWORD`/`DB_NAME` | Database connection |
| `-email` | `ADMIN_EMAIL` | Admin email (required) |
| `-name` | `ADMIN_NAME` | Display name (defaults to email prefix) |
| `-role` | — | `super_admin`, `ops_admin`, `readonly` (primary only) |
| `-backup-email` | `ADMIN_BACKUP_EMAIL` | Break-glass backup administrator (required unless `-no-backup`) |
| `-backup-name` | `ADMIN_BACKUP_NAME` | Backup display name (defaults to email prefix) |
| `-no-backup` | — | Skip the break-glass backup (not recommended; prints a warning) |
| `-force` | — | Delete and re-create an existing admin with the same email (and its sign-in account) |
| `-link` | — | Link an administrator created before sign-in accounts (v0.8 and older) to a new one and reactivate it (keeps role and authenticator) |

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
