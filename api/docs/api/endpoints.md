# API Reference

The authoritative, always-current reference is the OpenAPI spec generated from
the handler annotations. The public reference lives on the documentation
site (docs.openctem.io). A running API serves it as follows:

| Route | Outside production | Production (`APP_ENV=production`) |
|---|---|---|
| `GET /openapi.yaml` (the spec) | public | signed-in users only |
| `GET /docs` (interactive reference) | public | not served |
| `GET /api/v1/admin/docs`, `GET /api/v1/admin/openapi.yaml` | platform administrators (console session) | platform administrators (console session) |

The reference page loads one version-pinned script with a subresource
integrity hash and builds no URL from the request's `Host` header.

Locally, `make generate` at the repository root writes it to
`api/api/openapi/swagger.yaml`. Route style rules: [API conventions](../architecture/api-conventions.md).
This page covers what the spec does not: how to authenticate, the common
response shapes, rate limits and input validation.

## Authentication

| Caller | Credential | Notes |
|---|---|---|
| Web console and scripts acting as a user | `Authorization: Bearer <access token>` (or the console's session cookie) | Access tokens are short-lived (default 15 minutes) and scoped to one organization |
| Automation | Tenant API key: `Authorization: Bearer oct_…` or `X-API-Key: oct_…` | Read-only (GET/HEAD) on the REST API, limited to its scopes and to what its user can still do; see [API keys](../architecture/api-keys.md) |
| Sensors | Sensor key (`octs_…`) on `/api/v2/sensor/*` only | See [sensor identity](../architecture/agent-identity.md) |
| CI jobs | OIDC token exchanged for a run token on `/api/v1/ci/*` | See [Connect CI pipelines](../how-to/connect-ci-pipelines.md) |
| Platform admin console | Console session cookie on `/api/v1/admin/*` only | |

`AUTH_PROVIDER` selects how users sign in: `local` (built-in accounts),
`oidc` (an external OIDC provider such as Keycloak) or `hybrid` (both).
Organizations can also use their own SSO (OIDC or SAML); see the SSO
documentation at [docs.openctem.io](https://docs.openctem.io).

### Local sign-in flow

1. **Login** returns a refresh token and the user's organizations.
2. **Exchange** the refresh token for an access token scoped to one
   organization.

```bash
# Login
curl -X POST "https://openctem.example.com/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "<password>"}'

# Exchange for an organization-scoped access token
curl -X POST "https://openctem.example.com/api/v1/auth/token" \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>", "tenant_id": "<organization id>"}'
```

Public registration (`POST /api/v1/auth/register`) is off by default; accounts
come from an administrator, an invitation or the organization's SSO.

## Errors

User and admin routes return the `pkg/apierror` envelope:

```json
{
  "code": "NOT_FOUND",
  "message": "asset not found",
  "details": {}
}
```

`details` is optional.

`code` is the machine-readable contract. The sensor plane (`/api/v2/sensor/*`)
returns RFC 9457 `application/problem+json`. Status codes:

| Situation | Status |
|---|---|
| malformed input | 400 |
| not authenticated | 401 |
| not allowed, or module off (`MODULE_NOT_ENABLED`) | 403 |
| outside the caller's organization or data scope | 404 (never 403, so existence is not confirmed) |
| state conflict | 409 |
| validation failed | 422 |
| rate limited (with `Retry-After`) | 429 |

## Pagination, sorting and filtering

```
GET /api/v1/assets?page=1&per_page=20&sort=-created_at
```

```json
{ "data": [...], "total": 150, "page": 1, "per_page": 20, "total_pages": 8 }
```

`per_page` defaults to 20 (max 100). Append-only collections (audit logs,
events) use `cursor` / `next_cursor`. Filters follow the list query contract
([list-query-contract.md](../architecture/list-query-contract.md)). Some older
routes still accept their earlier parameter names; check the spec.

## Rate limits

Besides the general API limiter (`RATE_LIMIT_*`) and the sign-in limits
([Redis guide](../redis-production-guide.md#authentication-rate-limits)), scan
starts are limited per organization:

| Endpoint | Limit |
|---|---|
| `POST /api/v1/scans/{id}/trigger` | 20 per minute |
| `POST /api/v1/scans/quick` | 10 per minute |

A limited request gets `429` with `Retry-After` (whole seconds, at least 1).
Every rate-limit middleware, including the per-key hourly limit of `oct_` API
keys and the per-connection limit of the MCP endpoint, also sends the
rate-limit state in two header families (the API-key and MCP limits only on the
`429`):

| Header | Meaning |
|---|---|
| `RateLimit-Limit` | requests the window allows (the bucket depth) |
| `RateLimit-Remaining` | requests left; 0 on a 429 |
| `RateLimit-Reset` | seconds until the allowance is full again |
| `X-RateLimit-Limit`, `X-RateLimit-Remaining` | same values as above |
| `X-RateLimit-Reset` | the reset moment as a Unix timestamp |

The `X-RateLimit-*` names are kept for one deprecation window and then dropped;
use the `RateLimit-*` names in new clients. A `429` from a cool-down or a
one-at-a-time guard inside a route (a running export, a dashboard rebuild) has
the error body only.

## Input validation for scan configuration

Scan and scan workflow step configuration is validated before it is stored or
dispatched (`internal/app/security_validator.go`):

- values with shell metacharacters, command substitution or path traversal are
  refused;
- these keys are refused anywhere in a config: `command`, `cmd`, `exec`,
  `execute`, `shell`, `bash`, `sh`, `script`, `eval`, `system`, `popen`,
  `subprocess`, `spawn`, `run_command`, `os_command`, `raw_command`,
  `custom_command`.

A refused config answers `400` and is audited (`security.validation_failed`).
