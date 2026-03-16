# OpenCTEM REST API Documentation

The OpenCTEM API provides programmatic access to Continuous Threat Exposure Management operations including asset inventory, vulnerability findings, scan orchestration, and exposure management.

## Base URL

All API endpoints are served under the `/api/v1/` prefix:

```
https://your-instance.example.com/api/v1/
```

## Authentication

### JWT Bearer Token (Users)

Obtain a token pair via `POST /api/v1/auth/login`, then include the access token:

```
Authorization: Bearer <access_token>
```

Access tokens are short-lived (default 15m). Use the refresh endpoint to rotate tokens.

### API Key (Agents)

Platform agents authenticate via the `X-API-Key` header. Keys are scoped to a specific tenant and agent.

```
X-API-Key: <agent_api_key>
```

## Endpoint Groups

| Group | Prefix | Description |
|-------|--------|-------------|
| **Auth** | `/auth/` | Login, registration, token refresh, OAuth, sessions |
| **Users** | `/users/`, `/me/` | User profile, preferences, membership |
| **Tenants** | `/tenants/` | Tenant management, members, invitations |
| **Assets** | `/assets/` | Asset inventory, services, relationships, state history |
| **Findings** | `/findings/` | Vulnerability findings, activities, AI triage, suppression |
| **Scans** | `/scans/`, `/pipelines/` | Scan definitions, pipelines, scan sessions, triggers |
| **Tools** | `/tools/`, `/tool-categories/` | Tool registry, categories, scanner templates |
| **Agents** | `/agents/`, `/agent/` | Agent management (JWT) and agent communication (API key) |
| **Integrations** | `/integrations/` | Third-party integrations, notifications |
| **Scope** | `/scope/` | Scope configuration for CTEM programs |
| **Workflows** | `/workflows/` | Automated workflow definitions and triggers |
| **Exposures** | `/exposures/` | Exposure management, threat intelligence, credentials |
| **Access Control** | `/groups/`, `/roles/`, `/permission-sets/` | RBAC groups, roles, permissions |
| **Platform Agents** | `/platform/`, `/platform-jobs/` | Platform-managed agent registration, jobs, leases |
| **Dashboard** | `/dashboard/` | Aggregated statistics and metrics |
| **Audit** | `/audit/` | Audit log queries |
| **Admin** | `/admin/` | Platform administration (separate auth) |

## Request / Response Format

All request bodies must be JSON with `Content-Type: application/json`. Successful collection responses include pagination metadata:

```json
{
  "data": [ ... ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 142,
    "total_pages": 8
  }
}
```

### Error Responses

```json
{
  "error": {
    "code": "validation_error",
    "message": "Invalid input",
    "details": [{ "field": "name", "message": "name is required" }]
  }
}
```

| Code | Meaning |
|------|---------|
| `400` | Bad Request -- validation error or malformed input |
| `401` | Unauthorized -- missing or invalid authentication |
| `403` | Forbidden -- insufficient permissions |
| `404` | Not Found -- resource does not exist |
| `409` | Conflict -- duplicate or state conflict |
| `429` | Too Many Requests -- rate limit exceeded |
| `500` | Internal Server Error |

## Pagination

| Parameter | Default | Description |
|-----------|---------|-------------|
| `page` | `1` | Page number (1-indexed) |
| `page_size` | `20` | Items per page (max 100) |
| `sort_by` | varies | Sort field (e.g., `created_at`, `name`, `severity`) |
| `sort_order` | `desc` | Sort direction (`asc` or `desc`) |

## Filtering

Most list endpoints support filtering via query parameters:

```
GET /api/v1/findings?severity=critical&status=open&sort_by=created_at&sort_order=desc
```

## Rate Limiting

Default limits are **100 requests/second** with a burst of **200**. Specific endpoints (AI triage, scan triggers, test notifications) have stricter per-user limits. When rate limited, the API returns `429` with a `Retry-After` header.

## Health Check

`GET /health` returns `200 OK` when the API is operational. No authentication required.

## WebSocket

Real-time updates (finding activities, scan progress, notifications) are delivered via WebSocket at `/api/v1/ws`, using JWT authentication.

## OpenAPI Specification

```bash
go install github.com/swaggo/swag/cmd/swag@latest
swag init -g cmd/server/main.go -o docs/api
```
