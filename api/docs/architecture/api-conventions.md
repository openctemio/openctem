# API conventions

This is the short style guide every new or changed HTTP route follows.

- The reasoning, the inventory behind it and the migration plan are in
  [RFC-041](../rfcs/RFC-041-api-path-design.md).
- Status: **Accepted** with RFC-041 (owner decisions 2026-10-03). Existing
  routes that differ are recorded in a baseline and converge over time.
- Rules marked **(lint)** are enforced by `tools/lint/routestyle` (RFC-041
  §7). The plane table is `internal/infra/http/routes/plane`.

## 1. Planes

Every route belongs to exactly one plane. You can tell the plane from the
path prefix, and each plane has one authenticator. **(lint)**

| Plane | Prefix | Authenticator | Notes |
|---|---|---|---|
| user | `/api/v1/` | session JWT/cookie, `oct_` key | tenant **from the credential** |
| self | `/api/v1/me/` | session | the caller's own account; the only place that lists several tenants |
| auth | `/api/v1/auth/` | none, rate-limited | login, SSO, OAuth, SAML |
| admin | `/api/v1/admin/` | admin session / `X-Admin-API-Key` | platform admin; may be served on its own host |
| sensor | `/api/v2/sensor/` | sensor key (`octs_`), enrollment token (`octe_`) | new sensor calls are protocol v2 features advertised by `GET /api/v2/sensor/hello` |
| inbound | `/hooks/{provider}` (legacy `/api/v1/webhooks/incoming/`) | HMAC per tenant | |
| scim | `/scim/v2/` | SCIM bearer | casing mandated by RFC 7644 |
| mcp | `/api/v1/mcp` | `oct_` key | |
| ops | `/health`, `/ready`, `/metrics` | none / metrics bearer | `/metrics` and `/ready` are never exposed publicly |

The same table drives the public gateway. `PlaneEdges` and `EdgeOverrides`
(`routes/plane/edge.go`) say how the edge treats each plane: straight to the
API (sensor, inbound, scim, mcp, ops, and the IdP-facing auth paths),
through the web app's BFF (user, self, auth and admin, which browsers call
with a session cookie), or never (`/metrics`, `/ready`).
`api/deploy/gateway/planes.caddy` is generated from it
(`UPDATE_GATEWAY_PLANES=1 go test ./internal/infra/http/routes/plane/`), and a
test fails when the committed file and the table disagree. A new plane or
prefix therefore reaches the edge in the same PR, or CI is red.

Rules:

- A credential is accepted only on its own plane:
  - `octs_` and `octe_` only on the sensor plane;
  - `oct_` only on the user and MCP planes;
  - admin credentials only on the admin plane.
- A handler is mounted on one plane. If two realms need the same logic, give
  each its own handler wrapper.
- **Closed prefixes. Add nothing under them (lint):**
  - `/api/v1/agent/` (sensor protocol v1)
  - `/api/v1/agents/` (308 redirects)
  - `/api/v1/tenants/{tenant}/`
  - `/api/v1/users/me/`
  - `/api/v1/webhooks/incoming/`

## 2. Tenancy

- **The tenant comes from the credential.**
  - No `{tenant}`, `{tenant_id}` or `{org}` path parameter outside the admin,
    auth and inbound planes. **(lint)**
  - Settings of the caller's current organization live under the token
    singleton (`/api/v1/organization/...`, name pending RFC-041 D2), not
    under `/tenants/{tenant}`.
- **Inbound webhooks may name a tenant** (`?tenant=`), but only to choose
  which tenant secret the signature is verified against. The tenant is never
  trusted before that check.
- **The admin plane is cross-tenant by nature.** It addresses organizations
  as `/api/v1/admin/tenants/{tenant_id}`.

## 3. Paths

- **Lowercase kebab-case static segments**, `^[a-z][a-z0-9-]*$`. **(lint)**
- **Plural collections:** `/findings`, `/scan-zones`.
  - Singletons are allowed when there is exactly one per caller or per
    tenant: `/me`, `/organization`, `/settings`, `/dashboard`.
  - Module areas such as `/pentest`, `/compliance` and `/threat-intel` group
    their collections and are not collections themselves. **(lint)**
- **Path parameters are `{snake_case}`.** Identifiers end in `_id`:
  `{finding_id}`, `{scan_zone_id}`.
  - A collection uses the same parameter name everywhere.
  - The OpenAPI spec uses the same name as the router. **(lint)**
- **Nesting:** at most two parent collections and six segments after the
  version. When a child has its own identity, also give it a top-level
  collection, e.g. `/pipeline-runs` beside `/pipelines/{pipeline_id}/runs`.
  **(lint)**
- **Alternate keys are filters or `GET` lookups, not path segments.**
  - Use `GET /vulnerabilities?cve_id=CVE-2024-1234`, not
    `/vulnerabilities/cve/{cve_id}`.
  - When an alternate key must address a single resource, use
    `GET /tools/by-name/{name}` and nothing else.
- **No trailing slash and no file extensions.**
- **No secrets in the URL**, in the path or the query. Invitation, reset,
  enrollment and API tokens go in a header or the request body. **(lint)**
  - The one exception is the single-use WebSocket `ticket`, which browsers
    cannot send as a header. It is redacted at the edge.

## 4. Methods

| Operation | Method and path | Success |
|---|---|---|
| List | `GET /things` | 200 |
| Get | `GET /things/{thing_id}` | 200 |
| Create | `POST /things` | 201 + `Location` |
| Partial update | `PATCH /things/{thing_id}` (JSON merge: absent fields untouched) | 200 |
| Replace (whole document, e.g. a settings section) | `PUT /things/{thing_id}` | 200 |
| Delete | `DELETE /things/{thing_id}` | 204 |
| Aggregate view | `GET /things/stats` | 200 |
| Long-running job | `POST /things/exports` → 202 + `Location: /things/exports/{export_id}`, then `GET` it | 202 / 200 |

`GET` never changes state (RFC 9110 §9.2.1). **(lint)**

A `GET` may end in `export`, `download`, `preview` or `compare`, because
those name a read (a document, a preview, a comparison). Auth-plane paths
follow the protocols they implement (OAuth, SAML, OIDC) and are exempt from
the collection and action rules.

### 4.1 Custom methods (actions)

An action that does not fit the standard methods is a POST to a verb under
the resource:

```
POST /{collection}/{id}/{verb}
POST /{collection}/{verb}            (collection-wide)
```

- The verb is the last segment. It is POST only, and never GET, PATCH or
  DELETE on a verb path. **(lint)**
- **The vocabulary is closed. Use these words:**
  - `enable` / `disable` (not `activate`/`deactivate`)
  - `approve` / `reject`
  - `cancel`, `retry`, `run`, `test`, `verify`, `preview`, `apply`
  - `sync`, `import`, `export`
  - `resolve` / `reopen`
  - `suspend` / `reactivate`
  - `revoke`, `rotate`, `claim`, `release`, `start`, `complete`, `fail`
- Adding a verb is a reviewed change to the lint's list.
- Do not use a verb when the change is plain state with no side effects.
  `PATCH /notifications/{id}` with `{ "read": true }` is better than
  `PATCH /notifications/{id}/read`.
- Status that an action produces is a noun resource. Use
  `GET /threat-intel/sync-status`, not `GET /threat-intel/sync`.

### 4.2 Bulk

```
POST /{collection}/bulk/{verb}     body: { "ids": [...], ...arguments }
```

- Up to 1,000 ids.
- The response reports per-id results:
  `{ "succeeded": [...], "failed": [{ "id": ..., "code": ... }] }`.
- Use `bulk/delete` for deletion. Never send a `DELETE` with a body.

## 5. Query parameters

- **snake_case.** **(lint, over the spec)**
- **Pagination:**
  - Default: `page` (1-based) and `per_page` (default 20, max 100,
    larger values clamped). The response is
    `{ "data": [...], "total": n, "page": p, "per_page": k, "total_pages": t }`
    (`pkg/pagination`).
  - Exports and unbounded or append-only collections (audit logs, events,
    telemetry) use `cursor` with `next_cursor`. An empty `next_cursor` means
    the end. Cursors are opaque.
  - Do not add `limit`/`offset` or `page_size` to new routes.
- **Sorting:** `sort=field,-other` (a leading `-` means descending). Do not
  add `sort_by`/`sort_order`/`order`/`order_by` to new routes.
- **Filtering** follows [RFC-048](../rfcs/RFC-048-list-query-contract.md)
  ([how to use it](list-query-contract.md)). It supersedes the older
  plural / `min_` / `search` style, which stays only as deprecated aliases on
  migrated endpoints:
  - The param is the **singular response field name**; a list value uses
    commas, e.g. `severity=critical,high`.
  - Operators are suffixes: `_not`, `_gte`, `_gt`, `_lte`, `_lt`, `_null`,
    `_contains`, e.g. `cvss_score_gte=7`, `last_seen_at_gte=-P30D`.
  - Booleans use `is_`/`has_`, e.g. `is_in_kev=true`.
  - Free text is `q`.
  - OR and nesting: `POST /{collection}/search` with a FilterDocument.
  - A bad value, an unknown param (after the warn release) or an unsortable
    field is `400 INVALID_FILTER`.

## 6. Bodies and errors

- JSON field names are snake_case. Timestamps are RFC 3339 UTC. Identifiers
  are lowercase UUID strings.
- **User and admin planes** return the envelope from `pkg/apierror`:
  `{ "error": "...", "code": "UPPER_SNAKE", "message": "...", "details": ..., "request_id": "..." }`.
  - `code` is the machine-readable contract.
  - Add new codes to `pkg/apierror`. Do not invent them in handlers.
- **Sensor v2 and new planes** return RFC 9457
  `application/problem+json`, with `code` as an extension member. The user
  plane serves it on `Accept: application/problem+json` (RFC-041 D9).
- **Status codes:**

  | Situation | Status |
  |---|---|
  | malformed input | 400 |
  | not authenticated | 401 |
  | authenticated but not allowed, or module off (`MODULE_NOT_ENABLED`) | 403 |
  | out of the caller's tenant or data scope | 404 |
  | state conflict | 409 |
  | validation failed | 422 |
  | rate limited, with `Retry-After` | 429 |

  Never return 403 for out-of-scope objects, because that confirms the
  object exists.

## 7. Versioning and deprecation

- **The major version is in the path, per plane.** Within a major version,
  changes are additive only: new routes, new optional fields, new enum
  values that clients must tolerate.
- **A rename is a remove plus an add** (AIP-180). Keep the old path as an
  alias on the **same handler and the same middleware chain**, wrapped in
  `Deprecated(successor, deprecatedAt, sunsetAt)`. Every response then
  carries:

  ```
  Deprecation: @<unix seconds>                     (RFC 9745)
  Sunset: <IMF-fixdate>                            (RFC 8594, not earlier than Deprecation)
  Link: <successor>; rel="successor-version"
  ```

  and increments `deprecated_route_requests_total{plane,route,client}`.
- **Mark the operation `deprecated: true` in the spec.**
- **Remove it on the date only after the telemetry is at zero:**
  - web-only routes: 30 days;
  - external routes: 30 days, and at least 6 months after `Deprecation`;
  - sensor protocol: RFC-029 §5.4.

  Removal first answers `410 Gone` with a problem naming the successor for
  one release, then deletes the route.
- **Sensors:** a new or moved sensor route ships as a protocol v2 feature in
  `hello`. The SDK falls back while the feature is absent.

## 8. Documentation and checks

- **Every new route has a `// @Router` annotation.** Run `make swagger`. The
  `openapicontract` test fails otherwise. `undocumented-routes.txt` only
  shrinks.
- **Every new route has an authorization gate or an allowlist entry with a
  reason** (`tests/unit/route_authz_coverage_test.go`).
- **Every new route passes `routestyle`.** Its baseline
  (`api/openapi/route-style-baseline.txt`) only shrinks.
- **The web calls only routes that exist.** The phantom-call test checks
  `endpoints.ts` against the generated spec (RFC-041 §7).
