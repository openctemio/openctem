# Tenant API keys (`oct_`)

A tenant API key is a long-lived credential for automation and AI clients. It
is minted by a signed-in user in the UI (Settings, API keys) or with
`POST /api/v1/api-keys`, and the plaintext `oct_…` value is shown once.

A key works in two places:

| Where | What it can do |
|---|---|
| `POST /api/v1/mcp` | The read-only MCP server ([mcp-server.md](./mcp-server.md)). |
| Tenant REST routes (`/api/v1/assets`, `/api/v1/findings`, …) | **Read-only**: `GET`/`HEAD`, within the key's scopes. |

Sensor keys (`octs_…`, legacy `rda_…`; see [agent-identity.md](agent-identity.md#credential-formats)), SCIM tokens and the admin console
are separate credentials and are not covered here.

## What a key carries

| Field | Meaning |
|---|---|
| `tenant_id` | The only tenant the key can act in. Taken from the key, never from the request. |
| `user_id` | The user who minted it. The key acts as this user. |
| `scopes` | Permissions, validated against `permission.AllPermissions()` and against the creator's own permissions when minted. |
| `rate_limit` | Requests per hour (0 = unlimited). |
| `expires_at`, `status` | Expiry and revocation. |
| `last_used_at`, `last_used_ip`, `use_count` | Updated on every authenticated request. |

Who sees which keys: owners and administrators list every key of the
organization; anyone else (`integrations:api_keys:read` without the admin
bypass) lists only the keys whose `user_id` is their own, and another user's
key reads as 404 (owner decision 2026-10-02). Minting, revoking and deleting
need `integrations:api_keys:write` / `:delete`, which only owners and
administrators hold by default.

Storage: HMAC-SHA256 of the key with `APP_ENCRYPTION_KEY` as pepper (legacy
plain-SHA256 rows still match). Lookup is by hash, so the plaintext is never
compared.

## Using a key

```
GET /api/v1/findings?severity=critical
Authorization: Bearer oct_…
```

or `X-API-Key: oct_…`. Keys are never read from the query string. If both
headers are present they must carry the same key. A request that presents a
key is decided by the key alone: an invalid key is `401`, even if the request
also carries a session cookie.

## What the request may do

Every request re-checks the key. The permissions it gets are:

```
effective = key.scopes ∩ (what the key's user holds now)
```

An owner or admin holds everything, so their keys keep exactly their scopes;
anyone else's key loses a scope as soon as the user loses that permission.
A key is never an admin: the owner/admin bypass never applies, so a route the
key has no scope for is `403`.

Every key expires: `expires_in_days` is required, 1 to 365 (settings decision
B14). Keys minted before this rule without an expiry keep working. A member
may revoke or delete only their own keys (someone else's key reads as `404`);
an owner or administrator may revoke or delete any key of the organization.

The key is refused (`401`) when it is unknown, revoked or expired, when its user
is no longer an active member of the tenant (suspended or removed), when the
user's account is not active, or when the user's permissions cannot be read.
All of these give the same response.

On the REST API a key also:

- is **read-only**. `POST`, `PUT`, `PATCH` and `DELETE` are `403 API keys are
  read-only`, whatever the scopes. See "Open decision" below.
- is refused (`403`) on these areas, whatever the scopes: `/api/v1/api-keys`,
  `/api/v1/scim-tokens`, `/api/v1/me`, `/api/v1/notifications`, `/api/v1/ws`,
  `/api/v1/platform`, `/api/v1/users`, `/api/v1/auth`, `/api/v1/admin`,
  `/api/v1/tenants`, `/api/v1/invitations`. A key can never mint, list or
  revoke keys, change a password or 2FA, or reach the admin console.
- runs the same chain as a session after authentication: the key's user is
  loaded (UserSync), active membership is re-checked, the organization's IP
  allowlist applies, and the read rate limit applies.
- is accepted only on the token-tenant chains (`buildTokenTenantMiddlewares`).
  Routes on other chains (`/tenants/{tenant}/…`, the global vulnerability
  catalog, `/users/…`) stay JWT-only.

Rate limiting: each key has one token bucket sized from `rate_limit`, shared by
MCP and REST (`429` when exhausted).

CSRF: a key is sent in a header a cross-site page cannot set, so a key request
needs no CSRF token. It is never marked cookie-authenticated, the session
cookie is not read, and since key requests are read-only there is no state
change for a forged request to cause.

Audit: an audit entry written during a key request records the key's user as
the actor and adds `auth_method=api_key`, `api_key_id` and `api_key_prefix` to
its metadata (`auditapp.WithAPIKeyActor`).

## Code

| Piece | Where |
|---|---|
| Authentication, effective permissions | `internal/app/apikey/service.go` (`AuthenticateWithPermissions`) |
| Membership, account and holder checks | `internal/app/apikey/holder.go` |
| HTTP: MCP (`Handler`) and REST (`OrJWT`), denylist, rate limit | `internal/infra/http/middleware/apikey_auth.go` |
| Wiring into the token-tenant chains | `internal/infra/http/routes/routes.go` (`apiKeyOrJWT`) |
| Key user loaded for the chain | `internal/infra/http/middleware/user_sync.go` |
| Permission sync skipped for keys | `internal/infra/http/middleware/permission_sync.go` |

Tests: `internal/infra/http/routes/apikey_rest_db_test.go` (real routes and
database), `internal/infra/http/middleware/apikey_rest_auth_test.go`,
`tests/unit/apikey_service_test.go`, and
`tests/unit/apikey_route_policy_test.go`, which fails when a new route without
a permission gate is reachable by a key.

## Open decision: write access

Keys are read-only on the REST API. Scopes can include write permissions
(`assets:write`, `findings:status`, …), but every key minted so far was minted
for the read-only MCP server, so honouring those scopes now would silently give
existing keys write access. Allowing writes needs an owner decision: either a
per-key "allow writes" flag set at mint time, or honouring write scopes only
for keys minted after the change. The denylist and the CSRF reasoning above
already hold for writes; the read-only check in `OrJWT` is the one switch.
