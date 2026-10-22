# API conventions

This is the short style guide every new or changed HTTP route follows.

- The reasoning, the inventory behind it and the migration plan are in
  [RFC-041](../rfcs/RFC-041-api-path-design.md).
- Status: **Accepted** with RFC-041, **amended 2026-10-22** by the public API
  review (RFC-041 §11, decisions D1–D16 as adopted). Existing routes that
  differ are recorded in a baseline and converge over time.
- A rule marked **Planned** is adopted but not enforced or built yet. Do not
  rely on it, and do not add code that contradicts it.
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
| admin | `/api/v1/admin/` | platform admin console session (cookie) only; no API key or bearer header | platform admin; may be served on its own host |
| sensor | `/api/v2/sensor/` | sensor key (`octs_`), enrollment token (`octe_`) | new sensor calls are protocol v2 features advertised by `GET /api/v2/sensor/hello` |
| inbound | `/hooks/` (Jira: `/hooks/jira-integrations/{integration_id}`, GitHub: `/hooks/github-integrations/{integration_id}`) | HMAC per integration | new receivers go under `/hooks/` |
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
  - `/api/v1/agent/` (sensor protocol v1, retired 2026-10-05; nothing is served)
  - `/api/v1/agents/` (the old management path, retired 2026-10-05)
  - `/api/v1/tenants/{tenant}/`
  - `/api/v1/users/me/`
  - `/api/v1/webhooks/incoming/` (the existing GitHub receiver stays)

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
  collection, e.g. `/scan-runs` beside `/scan-workflows/{id}/runs`.
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
  - `refresh` (recompute stored results now, such as a dashboard snapshot)
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
  `{ "code": "UPPER_SNAKE", "message": "...", "details": ... }` (`details` optional).
  - `code` is the machine-readable contract.
  - Add new codes to `pkg/apierror`. Do not invent them in handlers.
- **The sensor v2 plane** returns RFC 9457 `application/problem+json`, with
  `code` as an extension member. The user, admin, SCIM-adjacent and hook
  planes return only the envelope above; there is no `Accept` negotiation
  (RFC-041 D9, amended in §11). The envelope's additions are in §10.
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
- Incoming `Idempotency-Key` handling on mutating routes is **Planned**; do not
  rely on it.
- **Mark the operation `deprecated: true` in the spec.**
- **Classify the audience first.**
  - *Web-only* routes are every route that is not a `GET`, because API keys
    are read-only, plus any `GET` with no key or MCP traffic for 14 days.
    They get **no window**: remove or rename them in the same PR as the web
    change, and add them to `removed_routes_test.go`.
  - *External* routes are the `GET`s that keys reach, and the SCIM, hook,
    MCP, CI and sensor planes. They get a **90-day window** from the first
    release carrying the `Deprecation` header.
  - The sensor protocol keeps RFC-029 §5.4.
- **After the window**, and only with the telemetry at zero for 30 days, the
  route answers `410 Gone` (the standard envelope, with the successor in
  `details.successor` and the `Link` header) for one release train (two
  weeks), then is deleted.
- **Announce once:** a changelog fragment in the *Deprecated* category, an
  entry on the docs site "API deprecations" page (route, successor,
  `Deprecation` date, `Sunset` date), and `deprecated: true` plus `x-sunset`
  in the spec.
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

## 9. Adopted additions (RFC-041 §11)

These rules were adopted on 2026-10-22. **Shipped** means it holds today;
everything else is **Planned**. The decision numbers are RFC-041 §11 D1–D16.

### 9.1 Paths and bodies

- **Version (D1).** `/api/v1` stays per plane. There is no v2 redesign: the
  API converges in place under the deprecation policy of §7.
- **Path parameters (amends §3).** The leaf resource parameter is `{id}`;
  parent parameters are `{snake_case_id}`, for example
  `/scan-workflows/{workflow_id}/runs/{id}`. 769 routes already use `{id}` and
  the name is not on the wire; only the parent names reach generated clients.
  **Planned** (the lint and the baseline follow).
- **Create** returns `201` with a `Location` header and the resource body.
- **Partial update** is `PATCH` with merge semantics (absent untouched,
  `null` clears). `PUT` replaces a whole document only. A `PUT` request type
  whose fields are all optional is a lint finding. **Planned**
- **Bulk (amends §4.2).** The response is
  `200 { "succeeded": ["id"], "failed": [{ "id", "code", "message" }] }`.
  **Planned**
- **Strict bodies.** An unknown field is `400 VALIDATION_FAILED` with the
  field code `UNKNOWN_FIELD`, through one shared decoder that also caps the
  size. **Planned**
- **Secrets are write-only:** never echoed, shown once on create or rotate,
  `has_secret` and `secret_last4` in reads, never in a URL. **Shipped**
- **Tenant-supplied URLs** (webhooks, integrations, template sources) are
  validated with `httpsec.ValidateURL` and fetched with the safe client, with
  redirects refused or re-validated. **Planned** (a lint for raw
  `http.Client` use).

### 9.2 Reads

- **Lists (D6).** `{ "data": [...], "total", "page", "per_page",
  "total_pages", "next_cursor" }`. The key is `data`, never `items` or
  `results`; the existing `items`/`results` lists send both keys for one
  window. `total` is exact up to 10,000 rows; above that it is omitted and
  `total_is_estimate: true` with `estimated_total` is sent. The paging state
  is also sent in `X-Total`, `X-Total-Pages`, `X-Page`, `X-Per-Page`,
  `X-Next-Page` and `Link` (`rel=next|prev|first`). **Planned**
- **Keyset paging (D7).** `pagination=keyset&cursor=` on findings, assets,
  audit, events and activity. The cursor is opaque, HMAC-signed and bound to
  the tenant and the sort, so it cannot be forged across tenants. Offset
  paging stops at 10,000 rows. Append-only collections are keyset only.
  **Planned**
- **Sort (D8).** `sort=field,-field` only. An unknown field is
  `400 INVALID_SORT` listing the allowed fields. `sort_by`, `order_by` and
  `order` stay as aliases for the window, then go. **Planned**
- **Order is deterministic.** Every sort ends in `id`. **Shipped** for lists
  that sort through the shared `pagination.SortOption` helper; repositories
  with a hand-written `ORDER BY` are audited and fixed as they are touched.
  **Planned** for the rest.
- **Bounded reads.** No endpoint returns an unbounded set; bulk routes take at
  most 1,000 ids. **Shipped** for the reads and bulk routes the review found
  unbounded; a sweep of the remaining reads is **Planned**.
- **Field selection (D9).** There is no generic `fields=`: a projection would
  bypass per-field permission checks and complicate caching, and nobody
  asked for it. Resources with expansions use `include=` (allowlisted,
  permission-checked); list representations stay lean.
- **Conditional reads.** Single resources that change rarely (settings,
  bootstrap, catalogs) send `ETag` and answer `If-None-Match` with `304`.
  **Planned**

### 9.3 Writes and safety

- **Stale `If-Match` (D4).** `412` with `RESOURCE_CHANGED` and the current
  `ETag`, replacing `409 FINDING_CHANGED` and `409 SETTINGS_CONFLICT`. `428`
  is required only where a lost update is a security issue (scope, policy and
  approval objects). The only caller today is the web app, so there is no
  window. **Planned**
- **Idempotency (D12).** `Idempotency-Key` (at most 255 characters) is
  honoured on imports, ticket creation, operation-starting `POST`s and all
  service-account key writes. The record is a Postgres row keyed by tenant,
  credential, route and key hash, kept 24 hours. The same key with another
  body is `422 IDEMPOTENCY_KEY_REUSED`; while the first request is running
  it is `409 IDEMPOTENCY_KEY_IN_USE`; a replay carries
  `Idempotent-Replayed: true`. If the store is unavailable the answer is
  `503`, never a silent second write. **Planned**
- **Long-running work (D10).** One resource, `/api/v1/operations/{id}`,
  tenant-scoped and readable by its creator or a permission holder, for
  exports, large imports, recalculations and bulk AI triage:
  `{ id, kind, status: queued|running|succeeded|failed|canceled, progress,
  result_url?, error? }`. Starting one returns `202` with `Location` and
  `Retry-After`. `202` is reserved for this and for four-eyes "pending
  approval" (`Location: /approvals/{id}`). Exports above 10,000 rows become
  operations with a signed, single-tenant download that expires in one hour;
  synchronous streaming stays for 10,000 rows or fewer. **Planned**
- **Finding imports (D11).** `POST /findings/imports` (multipart) answers
  `201` with `Location` for a small file, or `202` with an operation for a
  large one. `GET /findings/imports/{id}` is the receipt:
  `{ status, source, scope, counts: { created, updated, reactivated, closed,
  untouched, skipped, failed }, by_severity, errors: [{ index, code }],
  started_at, finished_at, idempotency_key }`. `closed` is non-zero only when
  the import declares full coverage of an explicit scope (asset set and
  tool); a partial scan never closes findings. All nine importers use the
  same `counts` vocabulary. **Planned**

### 9.4 Credentials

- **Write access for keys (D3).** Personal `oct_` keys stay read-only.
  **Service-account** keys may carry write scopes from a curated
  `KeyWritable` permission list: finding triage, assign, status, comment and
  import; asset and asset-group writes; ticket and integration creation;
  remediation tasks; scan runs.
  - Every step-up route stays session-only, because step-up refuses keys.
  - The deny list (keys, SCIM tokens, service accounts, users, tenants,
    admin) stays as it is.
  - A key may carry its own CIDR allowlist on top of the organization's.
  - Writes are audited with `api_key_id`.
  - Expiry is at most 365 days, as for every key.
  **Planned**
- **SCIM tokens** get a required expiry (1 to 365 days) and a rotate
  endpoint. **Planned**

## 10. Errors in full (D2, D5)

One envelope on the user, admin, SCIM-adjacent and hook planes (sensor v2
keeps RFC 9457):

```json
{ "code": "FINDING_NOT_ASSIGNABLE", "message": "...", "request_id": "...",
  "details": { "fields": [ { "field": "assignee_id", "code": "NOT_FOUND" } ],
               "params": { } } }
```

- `code` is `UPPER_SNAKE`, specific, and listed in the registry
  `pkg/apierror/codes.go` with its status, description and params. The spec
  lists the codes per operation. **Planned** (the registry)
- `message` is English for logs and developers. The web app translates from
  `code` and `params` through the `errors.<CODE>` i18n keys (en and vi).
- `request_id` is always present and equals the `X-Request-ID` header.
  **Shipped** for every error written through `pkg/apierror` after the
  request-id middleware; the few answers written before it (the concurrency
  limit) or outside the envelope are **Planned**.
- Internal error text is never in `message`. `err.Error()` is allowed only
  for domain errors that are explicitly public.
- Domain errors map to codes in **one** `handler.WriteError(w, r, err)`; new
  local `handleError` mappers are a lint finding (shrink-only baseline).
  **Planned**
- Status codes: the table in §6 plus `412` (precondition failed), `428`
  (precondition required), `409` (state conflict) and `410` (a removed route,
  for one release train). An object outside the caller's tenant or data scope
  is `404` on reads and writes alike, including a principal named in a
  request body (a user or group of another organization). **Shipped** for the
  asset owner routes; the cross-tenant sweep for the rest is **Planned**.

## 11. Headers

Every response carries `X-Request-ID`. Every rate-limit middleware sends
`RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` (seconds until
the allowance is full), plus `Retry-After`, on its `429`; the shared limiters
also send them on the requests they allow. The per-key limit of API keys and
the per-connection limit of MCP send them only on a `429`. A `429` from a
cool-down or a one-at-a-time guard inside a route carries the error body only. The older `X-RateLimit-*` names (reset as a Unix time) are sent for
one window and then dropped. **Shipped** for the limiters that exist today.
Deprecated routes carry `Deprecation`, `Sunset` and
`Link rel="successor-version"` (§7).

## 12. Outbound webhooks (D16)

Tenant webhooks follow the Standard Webhooks signing scheme. **Planned**

- Headers `webhook-id`, `webhook-timestamp`,
  `webhook-signature: v1,<base64 HMAC-SHA256 of "id.timestamp.body">`.
- A per-endpoint `whsec_` secret, shown once, write-only, rotated with a
  24-hour overlap in which both signatures are sent. Rotation needs step-up.
- Body `{ type, version, id, occurred_at, tenant_id, data }`, `type` from a
  typed catalogue (`finding.created`, `scan.completed`, ...) served at
  `GET /webhook-event-types` with a JSON Schema per type; `version` is per
  type. An HMAC with a timestamp gives integrity and replay protection that a
  shared secret in a header does not.
- One delivery row per event and channel with its own retry state (backoff 1
  minute, 5 minutes, 30 minutes, 2 hours, 6 hours, 12 hours, 24 hours), so a
  failing channel is retried even when another succeeded.
  `POST /integrations/{id}/deliveries/{id}/redeliver` and
  `POST /integrations/{id}/test` exist. Redirects are refused.

## 13. The spec and clients (D13, D14)

- Two generated specs. The **public** spec (user, self, auth for clients,
  SCIM, hooks and MCP metadata) is served at `/openapi.yaml` and published on
  the docs site per release. The **console** spec, which adds the admin plane,
  is served only at `/api/v1/admin/openapi.yaml`. The build converts Swagger
  2.0 to OpenAPI 3.1. **Planned**
- Every public operation has an `operationId` derived from the handler name,
  one tag, `security`, a typed 2xx, and 400/401/403/404/429 references to the
  error schema; a list declares its paging parameters and the `data`
  envelope. **Planned** (a Spectral ruleset with a shrink-only baseline)
- The web app moves to a generated client on the 3.1 types so that a call to
  a missing route is a type error. A generated Go REST client is built only
  when the first external integrator asks; until then the spec is published.
  **Planned**
