# API Reference

## Authentication

The API supports multiple authentication providers:

- **Local Auth**: Built-in JWT authentication
- **OIDC/Keycloak**: External identity provider
- **Hybrid**: Both local and OIDC tokens accepted

### Headers

```
Authorization: Bearer <access_token>
```

### Local Authentication Flow

1. **Register** - Create a new account
2. **Login** - Get refresh token
3. **Create/Select Team** - Choose a team to work with
4. **Exchange Token** - Get tenant-scoped access token

```bash
# Register
curl -X POST "http://localhost:8080/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123", "name": "John Doe"}'

# Login
curl -X POST "http://localhost:8080/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Exchange for tenant-scoped token
curl -X POST "http://localhost:8080/api/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>", "tenant_id": "<tenant_id>"}'
```

---

## REST API

Base URL: `http://localhost:8080/api/v1`

### Health & Metrics (Public)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| GET | `/metrics` | Prometheus metrics |

### Authentication (Public)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/info` | Auth provider info |
| POST | `/auth/register` | Register new user |
| POST | `/auth/login` | Login (get refresh token) |
| POST | `/auth/token` | Exchange refresh token for access token |
| POST | `/auth/refresh` | Refresh tokens |
| POST | `/auth/logout` | Logout (requires auth) |
| POST | `/auth/verify-email` | Verify email address |
| POST | `/auth/forgot-password` | Request password reset |
| POST | `/auth/reset-password` | Reset password |
| POST | `/auth/create-first-team` | Create first team |

### User Profile

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/users/me` | Get current user profile | JWT |
| PUT | `/users/me` | Update profile | JWT |
| PUT | `/users/me/preferences` | Update preferences | JWT |
| GET | `/users/me/tenants` | List user's teams | JWT |
| POST | `/users/me/change-password` | Change password | JWT (local) |
| GET | `/users/me/sessions` | List sessions | JWT (local) |
| DELETE | `/users/me/sessions` | Revoke all sessions | JWT (local) |
| DELETE | `/users/me/sessions/:id` | Revoke session | JWT (local) |

### Teams (Tenants)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/tenants` | List user's teams | JWT |
| POST | `/tenants` | Create new team | JWT |
| GET | `/tenants/:tenant` | Get team details | JWT |
| PATCH | `/tenants/:tenant` | Update team | Team admin+ |
| DELETE | `/tenants/:tenant` | Delete team | Team owner |

### Team Members

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/tenants/:tenant/members` | List members | Team member |
| GET | `/tenants/:tenant/members?include=user` | List with user info | Team member |
| GET | `/tenants/:tenant/members/stats` | Get member statistics | Team member |
| POST | `/tenants/:tenant/members` | Add member | Team admin+ |
| PATCH | `/tenants/:tenant/members/:id` | Update role | Team admin+ |
| DELETE | `/tenants/:tenant/members/:id` | Remove member | Team admin+ |

#### Member Statistics Response

```json
{
  "total_members": 10,
  "active_members": 8,
  "pending_invites": 2,
  "role_counts": {
    "owner": 1,
    "admin": 2,
    "member": 5,
    "viewer": 2
  }
}
```

### Team Invitations

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/tenants/:tenant/invitations` | List invitations | Team member |
| POST | `/tenants/:tenant/invitations` | Create invitation | Team admin+ |
| DELETE | `/tenants/:tenant/invitations/:id` | Cancel invitation | Team admin+ |
| GET | `/invitations/:token` | Get invitation details | JWT |
| POST | `/invitations/:token/accept` | Accept invitation | JWT |

### Team Settings

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/tenants/:tenant/settings` | Get all settings | Team member |
| PATCH | `/tenants/:tenant/settings/general` | Update general settings | Team admin+ |
| PATCH | `/tenants/:tenant/settings/security` | Update security settings | Team admin+ |
| PATCH | `/tenants/:tenant/settings/api` | Update API settings | Team admin+ |
| PATCH | `/tenants/:tenant/settings/branding` | Update branding settings | Team admin+ |

#### General Settings

```json
{
  "timezone": "UTC",
  "language": "en",
  "industry": "technology",
  "website": "https://example.com"
}
```

#### Security Settings

```json
{
  "sso_enabled": false,
  "sso_provider": "saml",
  "mfa_required": false,
  "session_timeout_min": 60,
  "ip_whitelist": ["192.168.1.0/24"],
  "allowed_domains": ["example.com"]
}
```

#### API Settings

```json
{
  "api_key_enabled": true,
  "webhook_url": "https://example.com/webhook",
  "webhook_events": ["finding.created", "scan.completed"]
}
```

#### Branding Settings

```json
{
  "primary_color": "#3B82F6",
  "logo_dark_url": "https://example.com/logo-dark.png",
  "logo_data": "data:image/png;base64,..."
}
```

### Audit Logs

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/audit-logs` | List audit logs | `audit:read` |
| GET | `/audit-logs/stats` | Get audit statistics | `audit:read` |
| GET | `/audit-logs/:id` | Get single audit log | `audit:read` |
| GET | `/audit-logs/resource/:type/:id` | Get resource history | `audit:read` |
| GET | `/audit-logs/user/:id` | Get user activity | `audit:read` |

#### Audit Log Response

```json
{
  "id": "uuid",
  "tenant_id": "uuid",
  "actor_id": "uuid",
  "actor_email": "user@example.com",
  "action": "tenant.settings.updated",
  "resource_type": "tenant",
  "resource_id": "uuid",
  "resource_name": "My Team",
  "result": "success",
  "severity": "info",
  "message": "Security settings updated",
  "changes": {
    "mfa_required": { "old": false, "new": true }
  },
  "metadata": {},
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Audit Actions

- `tenant.created`, `tenant.updated`, `tenant.deleted`, `tenant.settings.updated`
- `member.added`, `member.removed`, `member.role.changed`
- `invitation.created`, `invitation.accepted`, `invitation.revoked`
- `finding.created`, `finding.updated`, `finding.resolved`
- `asset.created`, `asset.updated`, `asset.deleted`
- `project.created`, `project.updated`, `project.deleted`
- `user.login`, `user.logout`, `user.password.changed`

### Assets

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/assets` | List assets | `assets:read` |
| GET | `/assets/:id` | Get asset | `assets:read` |
| POST | `/assets` | Create asset | `assets:write` |
| PUT | `/assets/:id` | Update asset | `assets:write` |
| DELETE | `/assets/:id` | Delete asset | `assets:delete` |

### Projects

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/projects` | List projects | `projects:read` |
| GET | `/projects/:id` | Get project | `projects:read` |
| POST | `/projects` | Create project | `projects:write` |
| PUT | `/projects/:id` | Update project | `projects:write` |
| DELETE | `/projects/:id` | Delete project | `projects:delete` |

### Components

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/components` | List components | `components:read` |
| GET | `/components/:id` | Get component | `components:read` |
| POST | `/components` | Create component | `components:write` |
| PUT | `/components/:id` | Update component | `components:write` |
| DELETE | `/components/:id` | Delete component | `components:delete` |
| GET | `/projects/:id/components` | List project components | `components:read` |

### Findings

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/findings` | List findings | `findings:read` |
| GET | `/findings/:id` | Get finding | `findings:read` |
| POST | `/findings` | Create finding | `findings:write` |
| PATCH | `/findings/:id/status` | Update status | `findings:write` |
| DELETE | `/findings/:id` | Delete finding | `findings:delete` |
| GET | `/projects/:id/findings` | List project findings | `findings:read` |

### Vulnerabilities (Global CVE Database)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/vulnerabilities` | List vulnerabilities | `vulnerabilities:read` |
| GET | `/vulnerabilities/:id` | Get vulnerability | `vulnerabilities:read` |
| GET | `/vulnerabilities/cve/:cve_id` | Get by CVE ID | `vulnerabilities:read` |
| POST | `/vulnerabilities` | Create vulnerability | `vulnerabilities:write` |
| PUT | `/vulnerabilities/:id` | Update vulnerability | `vulnerabilities:write` |
| DELETE | `/vulnerabilities/:id` | Delete vulnerability | `vulnerabilities:delete` |

### Dashboard

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/dashboard/stats` | Tenant statistics | `dashboard:read` |
| GET | `/dashboard/stats/global` | Global statistics | `dashboard:read` |

### Agents

Agents are distributed components (scanners, collectors) that execute security tasks on tenant infrastructure.

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/agents` | List agents | `agents:read` |
| GET | `/agents/:id` | Get agent | `agents:read` |
| POST | `/agents` | Create agent (returns API key) | `agents:write` |
| PUT | `/agents/:id` | Update agent | `agents:write` |
| DELETE | `/agents/:id` | Delete agent | `agents:delete` |
| POST | `/agents/:id/regenerate-key` | Regenerate API key | `agents:write` |

#### Agent Types

| Type | Description |
|------|-------------|
| `runner` | CI/CD one-shot scans |
| `worker` | Server-controlled daemon |
| `collector` | Data collection agent |
| `sensor` | EASM sensor |

#### Agent Status

| Status | Description |
|--------|-------------|
| `pending` | Newly created, awaiting first connection |
| `active` | Connected and operational |
| `inactive` | Disconnected or idle |
| `error` | Encountered an error |
| `revoked` | Access revoked |

#### Create Agent Response

```json
{
  "agent": {
    "id": "uuid",
    "tenant_id": "uuid",
    "name": "my-scanner",
    "type": "runner",
    "execution_mode": "daemon",
    "status": "pending",
    "capabilities": ["sast", "sca"],
    "tools": ["semgrep", "trivy"],
    "api_key_prefix": "rda_abc12345",
    "created_at": "2024-01-15T10:30:00Z"
  },
  "api_key": "rda_abc12345..." // Only shown once on creation
}
```

### Tool Registry

The Tool Registry manages security tools available for scanning. It consists of two parts:
- **Tools**: Global tool definitions (system-wide)
- **Tenant Tool Configs**: Tenant-specific tool configurations and overrides

#### Tools (Global Registry)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/tools` | List all tools | `tools:read` |
| GET | `/tools/:id` | Get tool by ID | `tools:read` |
| GET | `/tools/name/:name` | Get tool by name | `tools:read` |
| GET | `/tools/category/:category` | List tools by category | `tools:read` |
| GET | `/tools/capability/:capability` | List tools by capability | `tools:read` |
| POST | `/tools` | Create tool | `tools:write` |
| PUT | `/tools/:id` | Update tool | `tools:write` |
| DELETE | `/tools/:id` | Delete tool (custom only) | `tools:delete` |
| GET | `/tools/stats` | Get tool statistics | `tools:read` |

#### Tool Categories

| Category | Description |
|----------|-------------|
| `sast` | Static Application Security Testing |
| `dast` | Dynamic Application Security Testing |
| `sca` | Software Composition Analysis |
| `secret` | Secret Detection |
| `container` | Container Security |
| `iac` | Infrastructure as Code scanning |
| `network` | Network Security |
| `osint` | Open Source Intelligence |
| `recon` | Reconnaissance |
| `exploit` | Exploitation Tools |
| `other` | Other tools |

#### Tool Response

```json
{
  "id": "uuid",
  "name": "semgrep",
  "display_name": "Semgrep",
  "description": "Fast, lightweight static analysis for finding bugs",
  "logo_url": "https://example.com/semgrep.png",
  "category": "sast",
  "install_method": "binary",
  "install_cmd": "pip install semgrep",
  "update_cmd": "pip install --upgrade semgrep",
  "version_cmd": "semgrep --version",
  "version_regex": "semgrep ([0-9.]+)",
  "current_version": "1.50.0",
  "latest_version": "1.51.0",
  "config_file_path": ".semgrep.yml",
  "config_schema": {},
  "default_config": {},
  "capabilities": ["sast", "code-analysis"],
  "supported_targets": ["repository", "directory"],
  "output_formats": ["json", "sarif"],
  "docs_url": "https://semgrep.dev/docs",
  "github_url": "https://github.com/returntocorp/semgrep",
  "is_active": true,
  "is_builtin": true,
  "has_update": true,
  "tags": ["python", "security", "linting"],
  "metadata": {},
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

#### Tool Statistics Response

```json
{
  "total": 15,
  "active": 12,
  "inactive": 3,
  "by_category": {
    "sast": 4,
    "sca": 3,
    "secret": 2,
    "container": 2,
    "network": 2,
    "recon": 2
  },
  "builtin": 10,
  "custom": 5,
  "with_updates": 3
}
```

#### Tenant Tool Configs

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/tenant-tools` | List tenant tool configs | `tenant-tools:read` |
| GET | `/tenant-tools/:tool_id` | Get config for tool | `tenant-tools:read` |
| POST | `/tenant-tools/:tool_id` | Create/update config | `tenant-tools:write` |
| DELETE | `/tenant-tools/:tool_id` | Delete config (reset to default) | `tenant-tools:delete` |
| POST | `/tenant-tools/:tool_id/activate` | Activate tool for tenant | `tenant-tools:write` |
| POST | `/tenant-tools/:tool_id/deactivate` | Deactivate tool for tenant | `tenant-tools:write` |
| GET | `/tenant-tools/active` | List active tools only | `tenant-tools:read` |

#### Tenant Tool Config Response

```json
{
  "id": "uuid",
  "tenant_id": "uuid",
  "tool_id": "uuid",
  "tool_name": "semgrep",
  "is_enabled": true,
  "priority": 1,
  "config_overrides": {
    "severity_threshold": "warning",
    "timeout_seconds": 600
  },
  "credentials": {
    "api_key_ref": "vault:semgrep-api-key"
  },
  "schedule": "0 2 * * *",
  "metadata": {},
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

#### Combined Tool with Config

GET `/tools/:id?include=config` returns tool with tenant-specific config:

```json
{
  "tool": { ... },
  "config": {
    "is_enabled": true,
    "priority": 1,
    "config_overrides": {}
  }
}
```

---

### Pipelines

Pipelines orchestrate multi-step security scan workflows.

#### Templates

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/pipelines` | List templates | `pipelines:read` |
| GET | `/pipelines/:id` | Get template with steps | `pipelines:read` |
| POST | `/pipelines` | Create template | `pipelines:write` |
| PUT | `/pipelines/:id` | Update template | `pipelines:write` |
| DELETE | `/pipelines/:id` | Delete template | `pipelines:delete` |

#### Steps

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| POST | `/pipelines/:id/steps` | Add step to template | `pipelines:write` |
| PUT | `/pipelines/:id/steps/:stepId` | Update step | `pipelines:write` |
| DELETE | `/pipelines/:id/steps/:stepId` | Delete step | `pipelines:delete` |

#### Runs

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/pipelines/:id/runs` | List runs for template | `pipelines:read` |
| POST | `/pipelines/:id/runs` | Trigger new run | `pipelines:write` |
| GET | `/pipeline-runs/:id` | Get run details with step runs | `pipelines:read` |
| POST | `/pipeline-runs/:id/cancel` | Cancel running pipeline | `pipelines:write` |

**Rate Limiting:** `POST /pipelines/:id/runs` is rate limited to 30 requests/minute per tenant.

#### Template Response

```json
{
  "id": "uuid",
  "tenant_id": "uuid",
  "name": "Full Security Scan",
  "description": "Comprehensive scan pipeline",
  "version": 1,
  "is_active": true,
  "triggers": [
    {
      "type": "schedule",
      "schedule": "0 2 * * *"
    },
    {
      "type": "webhook",
      "webhook": "unique-webhook-id"
    }
  ],
  "settings": {
    "max_parallel_steps": 3,
    "fail_fast": false,
    "retry_failed_steps": 2,
    "timeout_seconds": 3600,
    "notify_on_complete": true,
    "notify_on_failure": true
  },
  "steps": [
    {
      "id": "uuid",
      "step_key": "sast-scan",
      "name": "SAST Analysis",
      "order": 1,
      "capabilities": ["sast"],
      "tool": "semgrep",
      "config": {"rules": ["security-audit"]},
      "timeout_seconds": 1800,
      "depends_on": [],
      "max_retries": 2
    }
  ],
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

#### Trigger Types

| Type | Description |
|------|-------------|
| `manual` | Manually triggered via API |
| `schedule` | Cron-based schedule |
| `webhook` | Triggered by webhook |
| `api` | Triggered by API call |
| `on_asset_discovery` | Auto-trigger on new asset |

#### Run Status

| Status | Description |
|--------|-------------|
| `pending` | Run created, not started |
| `running` | Currently executing |
| `completed` | Finished successfully |
| `failed` | Failed with error |
| `cancelled` | Cancelled by user |
| `timeout` | Exceeded timeout |

---

### Scans

Scans bind asset groups with scanners/workflows and schedules to automate security scanning.

#### Scan Management

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/scans` | List scans | `scans:read` |
| GET | `/scans/stats` | Get scan statistics | `scans:read` |
| GET | `/scans/:id` | Get scan | `scans:read` |
| POST | `/scans` | Create scan | `scans:write` |
| PUT | `/scans/:id` | Update scan | `scans:write` |
| DELETE | `/scans/:id` | Delete scan | `scans:delete` |

#### Scan Status Operations

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| POST | `/scans/:id/activate` | Activate scan (enable scheduling) | `scans:write` |
| POST | `/scans/:id/pause` | Pause scan (suspend scheduling) | `scans:write` |
| POST | `/scans/:id/disable` | Disable scan | `scans:write` |

#### Scan Execution

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| POST | `/scans/:id/trigger` | Trigger scan execution manually | `scans:write` |
| POST | `/scans/:id/clone` | Clone scan configuration | `scans:write` |

**Rate Limiting:**
- `POST /scans/:id/trigger`: 20 requests/minute per tenant
- `POST /quick-scan`: 10 requests/minute per tenant (stricter)

#### Scan Runs (Sub-resource)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/scans/:scanId/runs` | List runs for scan | `scans:read` |
| GET | `/scans/:scanId/runs/latest` | Get latest run | `scans:read` |
| GET | `/scans/:scanId/runs/:runId` | Get specific run | `scans:read` |

#### Scan Types

| Type | Description |
|------|-------------|
| `workflow` | Execute a multi-step pipeline workflow |
| `single` | Execute a single scanner tool |

#### Schedule Types

| Type | Description |
|------|-------------|
| `manual` | Manually triggered only |
| `daily` | Run daily at specified time |
| `weekly` | Run weekly on specified day |
| `monthly` | Run monthly on specified day |
| `crontab` | Custom cron expression |

#### Scan Status

| Status | Description |
|--------|-------------|
| `active` | Scan is active and will run on schedule |
| `paused` | Scan is paused (scheduling suspended) |
| `disabled` | Scan is disabled |

#### Scan Response

```json
{
  "id": "uuid",
  "tenant_id": "uuid",
  "name": "Vulnerability Scan - Production Servers",
  "description": "Weekly vulnerability scan for production",
  "asset_group_id": "uuid",
  "scan_type": "workflow",
  "pipeline_id": "uuid",
  "scanner_name": null,
  "scanner_config": null,
  "targets_per_job": 30,
  "schedule_type": "weekly",
  "schedule_cron": null,
  "schedule_day": 1,
  "schedule_time": "02:00:00",
  "schedule_timezone": "UTC",
  "next_run_at": "2024-01-22T02:00:00Z",
  "tags": ["internal", "infra"],
  "run_on_tenant_runner": false,
  "status": "active",
  "last_run_id": "uuid",
  "last_run_at": "2024-01-15T02:00:00Z",
  "last_run_status": "completed",
  "total_runs": 10,
  "successful_runs": 9,
  "failed_runs": 1,
  "created_by": "uuid",
  "created_at": "2024-01-01T10:30:00Z",
  "updated_at": "2024-01-15T02:01:00Z"
}
```

#### Scan Statistics Response

```json
{
  "total": 15,
  "active": 10,
  "paused": 3,
  "disabled": 2,
  "by_schedule_type": {
    "manual": 3,
    "daily": 5,
    "weekly": 4,
    "monthly": 2,
    "crontab": 1
  },
  "by_scan_type": {
    "workflow": 12,
    "single": 3
  }
}
```

---

### Platform Agents (v3.2)

Platform agents are OpenCTEM-managed shared scanning infrastructure. Unlike tenant agents, platform agents are centrally managed and can process jobs from multiple tenants.

#### Agent Registration (Public)

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/platform/register/` | Register new platform agent | Bootstrap Token |

Rate limited to prevent brute-force attacks on bootstrap tokens.

**Request:**
```json
{
  "bootstrap_token": "bst_abc123...",
  "name": "scanner-us-east-1-01",
  "capabilities": ["scan", "recon"],
  "tools": ["nmap", "nikto"],
  "region": "us-east-1",
  "max_concurrent": 10,
  "version": "1.0.0",
  "hostname": "scanner-pod-abc123",
  "labels": {"env": "production"}
}
```

**Response:**
```json
{
  "agent": {
    "id": "uuid",
    "name": "scanner-us-east-1-01",
    "status": "active",
    "capabilities": ["scan", "recon"],
    "tools": ["nmap", "nikto"],
    "region": "us-east-1"
  },
  "api_key": "pag_..." // Only shown once
}
```

#### Agent Communication (API Key Auth)

These endpoints use API key authentication via headers:
- `X-Agent-ID: <agent_id>`
- `X-API-Key: <api_key>`

| Method | Endpoint | Description |
|--------|----------|-------------|
| PUT | `/platform/agent/lease` | Renew agent lease (heartbeat) |
| DELETE | `/platform/agent/lease` | Release agent lease (graceful shutdown) |
| POST | `/platform/agent/poll` | Long-poll for available jobs |
| POST | `/platform/agent/jobs/{jobID}/ack` | Acknowledge job receipt |
| POST | `/platform/agent/jobs/{jobID}/result` | Report job result |
| POST | `/platform/agent/jobs/{jobID}/progress` | Report job progress |

#### Lease Renewal (Heartbeat)

**PUT `/platform/agent/lease`**

```json
{
  "holder_identity": "pod-scanner-abc123",
  "lease_duration_seconds": 60,
  "current_jobs": 3,
  "max_jobs": 10,
  "cpu_percent": 45.5,
  "memory_percent": 62.0
}
```

**Response:**
```json
{
  "success": true,
  "resource_version": 42,
  "renew_time": "2024-01-15T10:30:00Z"
}
```

#### Job Polling

**POST `/platform/agent/poll`**

```json
{
  "max_jobs": 5,
  "capabilities": ["scan"],
  "timeout_seconds": 30
}
```

**Response:**
```json
{
  "jobs": [
    {
      "id": "uuid",
      "tenant_id": "uuid",
      "type": "scan",
      "priority": "high",
      "payload": {"target": "example.com"},
      "timeout_sec": 3600,
      "auth_token": "job_token_...",
      "created_at": "2024-01-15T10:00:00Z"
    }
  ],
  "poll_interval_hint": 5,
  "queue_depth": 10
}
```

#### Report Job Result

**POST `/platform/agent/jobs/{jobID}/result`**

```json
{
  "status": "completed",
  "findings_count": 5,
  "duration_ms": 12345,
  "result": {"findings": [...]}
}
```

#### Platform Jobs (Tenant API)

Tenants can submit jobs to be processed by platform agents.

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| POST | `/platform-jobs/` | Submit new job | `scans:write` |
| GET | `/platform-jobs/` | List tenant's jobs | `scans:read` |
| GET | `/platform-jobs/{id}` | Get job status | `scans:read` |
| POST | `/platform-jobs/{id}/cancel` | Cancel job | `scans:write` |

#### Bootstrap Tokens (Admin)

Admin endpoints for managing bootstrap tokens.

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| GET | `/admin/platform/bootstrap-tokens` | List tokens | Admin |
| POST | `/admin/platform/bootstrap-tokens` | Create token | Admin |
| DELETE | `/admin/platform/bootstrap-tokens/{id}` | Revoke token | Admin |

---

## Error Responses

All errors follow a consistent format:

```json
{
  "error": {
    "code": "ASSET_NOT_FOUND",
    "message": "Asset with ID xyz not found"
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Missing or invalid token |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `VALIDATION_ERROR` | 400 | Invalid request data |
| `CONFLICT` | 409 | Resource already exists |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Pagination

List endpoints support pagination:

```
GET /api/v1/assets?page=1&per_page=20&sort=name&order=asc
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `page` | 1 | Page number |
| `per_page` | 20 | Items per page (max 100) |
| `sort` | `created_at` | Sort field |
| `order` | `desc` | Sort order (asc/desc) |

Response includes pagination metadata:

```json
{
  "data": [...],
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 150,
    "total_pages": 8
  }
}
```

---

## Rate Limiting

### Trigger Endpoint Rate Limits

To prevent abuse and ensure fair resource usage, trigger endpoints are rate limited per tenant:

| Endpoint | Limit | Window | Scope |
|----------|-------|--------|-------|
| `POST /pipelines/:id/runs` | 30 | 1 minute | Per tenant |
| `POST /scans/:id/trigger` | 20 | 1 minute | Per tenant |
| `POST /quick-scan` | 10 | 1 minute | Per tenant (stricter) |

### Rate Limit Headers

All rate-limited endpoints return standard headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed in window |
| `X-RateLimit-Remaining` | Remaining requests in current window |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |
| `Retry-After` | Seconds to wait before retry (when limited) |

### Rate Limit Response

```json
{
  "code": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded. Please try again later.",
  "status": 429
}
```

---

## Security Validation

### Input Validation for Pipeline/Scan Operations

All pipeline step configs and scan configs are validated for security before execution.

### Blocked Patterns

The following patterns are blocked in config values:

| Category | Pattern | Example |
|----------|---------|---------|
| Shell metacharacters | `; & \| $ \`` | `target=example.com; rm -rf /` |
| Command substitution | `$(...)` or backticks | `target=$(whoami)` |
| Path traversal | `../` | `file=../../../etc/passwd` |
| Dangerous tools | `curl`, `wget`, `nc`, `bash` | `target=\| nc attacker.com` |

### Blocked Config Keys

The following config keys are not allowed:

```
command, cmd, exec, execute, shell, bash, sh, script,
eval, system, popen, subprocess, spawn, run_command,
os_command, raw_command, custom_command
```

### Validation Error Response

```json
{
  "code": "SECURITY_VALIDATION_FAILED",
  "message": "Config value contains potentially dangerous pattern",
  "status": 400
}
```
