# RFC-041: API path design, plane separation and a route style guard

> Status: **Accepted** (owner decisions 2026-10-03: D1–D12 approved as
> recommended, §8). Design PR #871. Implementation in progress (§10).
> Scope: `api/` (routes, OpenAPI, edge gateway), `web/` (API call sites,
> generated types), sdk-go and the sensor (only through the protocol v2
> feature negotiation of RFC-029), helm charts (edge rules).
> Related: RFC-016 (MCP), RFC-022 (admin console), RFC-023 (agent→sensor
> rename), RFC-029 (sensor protocol v2, v1 sunset), RFC-032 (enrollment),
> RFC-040 (sensor gateway, draft in #870).
> Companion: [`docs/architecture/api-conventions.md`](../architecture/api-conventions.md),
> the short style guide new routes follow.
>
> Owner's question (2026-10-03): should the API paths be redesigned to be the
> best they can be? Research deeply, propose the best option.

## 1. Answer in short

**No full redesign.** A v2 of the whole API would rename about 950
operations, double the exposed surface for a year, and break documented
callers. It would buy cosmetic consistency. The defects that matter are
narrower, and most of them are about security:

1. **Two tenant models.** 47 routes take the tenant from the path
   (`/api/v1/tenants/{tenant}/...`), and about 700 take it from the
   credential. The path-tenant routes run a different middleware chain
   that lacks four protections the token-tenant chain has (§3.2).
2. **The plane cannot be read from the path.** Sensor, admin, inbound-webhook
   and user routes cannot be split at the edge by prefix alone:
   - a sensor-authenticated route lives under a user namespace
     (`/api/v1/validation/evidence`);
   - the same handler serves both the sensor and the user realm;
   - the gateway routes requests by sniffing the `Authorization` and
     `X-API-Key` headers.

   RFC-040's sensor gateway needs a route table it can trust.
3. **The contract is incomplete and drifts.** 475 of 947 operations are
   undocumented (433 of them in a frozen baseline). 14 documented operations
   name their parameters differently in the spec and in the router, and the
   contract check hides this because it normalises names away. The web calls
   about 33 paths that have no route.
4. **There is no rule for new routes.** That is why the same idea is spelled
   several ways:
   - `activate`/`deactivate` and `enable`/`disable`;
   - four shapes for bulk operations;
   - five pagination dialects;
   - 46 different path-parameter names, including `{tenant}` and
     `{tenantId}` for the same resource.

**Recommended: Option B′.** Separate the planes on the prefixes that are
already exclusive, move only the routes that leak across planes, and close
the second tenant model.

- **Keep, unchanged:**
  - `/api/v2/sensor` is already the sensor plane, so no sensor path changes
    for that reason.
  - `/api/v1/admin` stays, and can additionally be served on its own
    hostname.
- **Move**, each with an alias that answers with `Deprecation`, `Sunset` and
  a successor `Link`, counted by a metric:
  - the invitation token, out of the URL;
  - sensor routes outside the sensor prefix, as v2 features the SDK
    negotiates;
  - `/tenants/{tenant}`, into a token-scoped `/api/v1/organization`.
- **Guard:** a route-style lint over the route table (the AST walk the
  authz-coverage test already uses) keeps every new route compliant, with a
  shrink-only baseline for today's debt.

Everything else (parameter names, verbs, pagination, errors) converges
opportunistically under the lint, not in one big bang.

## 2. Method

- **Route inventory.** An AST walk of
  `internal/infra/http/routes/*.go` follows chi `Group` nesting and resolves
  the `legacyv1`/`protov2` path constants, the same technique as
  `tests/unit/route_authz_coverage_test.go` and
  `tools/lint/openapicontract`. For each route it records the method, the
  full path, the handler expression, the group-level and route-level
  middleware (as source text) and the file and line.
  - Run on `develop` at commit `48ee874` (2026-10-03).
  - The tool is a scratch tool and is not committed. §7 proposes the
    committed version.
- **Plane classification.** By prefix and middleware chain:
  - sensor authenticator → sensor;
  - `AdminAuthMiddleware` → admin;
  - `RequireAdmin`/`RequireOwner`/`RequireTeamAdmin`, or a permission on
    members, roles, groups, keys, webhooks, integrations, settings, SCIM or
    audit → tenant-admin;
  - otherwise → user.

  The user/tenant-admin split is a heuristic, so read those two numbers as
  approximate.
- **OpenAPI.** `api/openapi/swagger.yaml` (Swagger 2.0, `basePath /api/v1`)
  and `api/openapi/sensor-protocol-v2.yaml` (OpenAPI 3.1), compared with the
  route set by method and path, both with and without parameter names.
- **Web.** Every non-test `.ts`/`.tsx` file in `web/src` was parsed with
  the TypeScript compiler. Constants, imports, the `endpoints.ts` builders
  and the admin-console client were resolved across files, and the method
  was read from the wrapper used (`get`/`post`/..., `method:`, the
  `useSWRMutation` fetcher). Paths were normalised (`${x}` → `{}`) and
  matched against the route table.
  - 105 SWR cache-invalidation keys and display-only strings were excluded.
  - Only **path-level** misses (no route at any method) are reported as
    phantoms, and those were spot-checked by hand.
  - Method-level mismatches were spot-checked, and most were artefacts of an
    id passed as a runtime argument.
- **Sensors.** The sdk-go tags v0.15.x and v0.16.x and `main`, the sensor
  tags v0.6.x and v0.7.0, and the asset-collector (which pins sdk-go
  v0.14.1), read from GitHub.
- **Edge and docs.** `deploy/gateway/Caddyfile`, the helm-charts gateway
  templates, `api/docs`, and the public `openctemio/docs` site.
- **Query parameters.** Every
  `Query().Get/Has`, `FormValue` and query-helper literal in
  `internal/infra/http/handler`.
- **Standards.** Read from the sources cited in §4.

## 3. Inventory

### 3.1 Size and planes

962 registrations collapse to **947 distinct method+path operations** on
**709 paths**. The 15 duplicates are `if/else` alternatives such as the WS
ticket chain and the metrics auth toggle.

| Plane | Routes | Prefix today | Authentication | In OpenAPI |
|---|---:|---|---|---:|
| User, token tenant | ~563 | `/api/v1/*` | session JWT/cookie, `oct_` key (read-only) | 277 |
| Tenant admin, token tenant | ~138 | `/api/v1/*` (mixed with user) | same, role or admin permission | 80 |
| Tenant admin, **URL tenant** | 47 | `/api/v1/tenants/{tenant}/*` | session only (`oct_` keys cannot reach it) | **5** |
| Tenant list / membership | 4 | `/api/v1/tenants`, `/module-presets` | session | 0 |
| Self (`/me`) | 30 | `/api/v1/me/*` **and** `/api/v1/users/me/*`, `/version`, `/ws` | session | 21 |
| Public auth flow | 30 | `/api/v1/auth/*`, `/api/v1/invitations/{token}*` | none / token / rate-limited | 17 |
| Platform admin console | 54 | `/api/v1/admin/*` | admin session cookie or `X-Admin-API-Key` | 43 |
| Sensor protocol v1 | 24 | `/api/v1/agent/*` (23) **+ `/api/v1/validation/evidence`** | sensor key | 17 |
| Sensor protocol v2 | 22 | `/api/v2/sensor/*` | sensor key only (others 401) | separate 3.1 doc |
| Inbound webhooks + SCIM | 17 | `/api/v1/webhooks/incoming/*` (2), `/scim/v2/*` (15) | HMAC / SCIM bearer | 0 |
| MCP | 1 | `/api/v1/mcp` | `oct_` key | 0 |
| Deprecated alias | 12 | `/api/v1/agents/*` → 308 `/api/v1/sensors` | n/a | 12 |
| Ops | 5 | `/health`, `/ready`, `/metrics`, `/openapi.yaml`, `/docs` | none / metrics bearer | 0 |

Other counts:

- **Version prefixes:**
  - `/api/v1`: 905
  - `/api/v2`: 22, all sensor protocol v2. Here "v2" is the protocol version,
    not an API version.
  - `/scim/v2`: 15, mandated by RFC 7644
  - unversioned: 5
- **Authorization:**
  - 676 routes carry a permission gate;
  - 63 carry a role gate;
  - 208 carry no route-level gate and sit under an allowlisted prefix
    (public, self, machine).
- **Web usage:** the web calls **579 distinct paths (791 method+path
  targets) from 1,159 call sites**: GET 528, POST 373, DELETE 122, PUT 85,
  PATCH 51.
  - The browser always calls its own origin. The Next.js route
    `app/api/v1/[...path]` forwards to the API unchanged and answers `421`
    to anything under `/api/v1/agent/*`.
  - `/api/v1/admin/*` has its own proxy that forwards only the admin
    cookies.
  - 239 routes are never called by the web. 81 of those are machine planes by
    design: sensor, inbound, MCP, ops and aliases.
  - The other 158 (98 user, 23 tenant-admin, 16 admin, 13 URL-tenant, 6 auth,
    2 self) are candidates for "dead or API-only". This RFC does not delete
    anything on that evidence alone, because API-key and MCP callers do not
    show up in the web.

### 3.2 Problems, ranked by impact

Impact is ranked on three questions:

- Can it cause a security defect?
- Does it break or mislead a consumer?
- Does it only look inconsistent?

#### P1. Two tenant models, and the second one has a weaker chain (security)

- **Token-tenant routes** (~700) take the tenant from the credential. They
  run `buildTokenTenantMiddlewares` (`routes.go`), which applies, in order:
  1. auth (JWT or `oct_` key)
  2. user sync
  3. SSO enforcement
  4. IP allowlist
  5. `RequireTenant`
  6. active membership
  7. permission sync
  8. CSRF overlay
  9. read rate limit
  10. data-scope guard
- **URL-tenant routes** (47 under `/api/v1/tenants/{tenant}`) build their own
  chain in `tenant.go`:
  1. auth
  2. user sync
  3. `TenantContext`, which resolves `{tenant}` as a UUID **or a slug**
  4. `RequireMembership`, a database check that the caller is a member of
     that tenant
  5. IP allowlist

  Isolation holds, because the server checks membership of the tenant named
  in the path. The chain is still weaker:

  - **No SSO-enforcement gate.** The comment at `routes.go` says the gate
    covers the URL-path chains, but `tenant.go` does not use
    `buildBaseMiddlewares`, so it does not run there. The gate is also keyed
    to the token's tenant, while these routes act on the path's tenant.
    Example: a user whose password session was minted in an organization
    without SSO acts on a second, SSO-enforced organization through
    `/tenants/{B}/settings/...`.
    *To verify with a test before filing as a bug;* this RFC reports it and
    does not fix it.
  - **No permission sync.** `RequireTeamAdmin` reads the role that
    `RequireMembership` loads, so this is mitigated, but the chain differs.
  - **No data-scope guard and no read rate limit.**
  - **42 of the 47 routes are undocumented.**

  The routes are not minor ones. They include security settings, the IP
  allowlist and API settings (`PATCH /settings/security`,
  `/settings/api`), data-scope policy, module toggles, members and roles.
- The admin console addresses tenants a third way:
  `/api/v1/admin/tenants/{tenantId}`.
- Every security vendor surveyed (§4.4) derives the tenant from the
  credential, never from the path. GitHub and Azure ARM use a path owner
  because one credential spans many owners. OpenCTEM's tokens are
  per-tenant, so the path tenant is redundant input that has to be checked.

#### P2. Planes are not separable by prefix (security, RFC-040)

- **A sensor-authenticated route sits in a user namespace.**
  `POST /api/v1/validation/evidence` uses `AuthenticateSource`, while
  `GET /api/v1/validation/coverage` beside it is a user route. RFC-040 §5.1
  has to list it by hand in the sensor-gateway route table.
- **The same handler is mounted in two realms.**
  `CredentialImportHandler.Import` serves both
  `POST /api/v1/agent/credentials/ingest` (sensor key) and
  `POST /api/v1/credentials/import` (user, permission-gated). A change for
  one realm silently changes the other.
- **The edge sniffs headers to find the plane.**
  `deploy/gateway/Caddyfile` sends to the API:
  - a 13-entry prefix list (`@api_paths`);
  - any `/api/*` carrying `Authorization: Bearer oct_*`;
  - any `/api/*` carrying `X-API-Key`;
  - any `/api/*` carrying a Bearer token without the session cookie.

  Everything else goes to the web. That works for "API vs web", but it
  cannot apply a per-plane WAF policy, body limit or rate limit, because the
  plane is defined by credential, not by path.
- **The edge list is maintained by hand in three places:** the Caddyfile,
  helm-charts `templates/_gateway.tpl` (Ingress and HTTPRoute) and the
  helm-charts copy of the Caddyfile.
- **The edge list is already stale.**
  - It routes `/api/v1/platform/*`, but the only route left there is
    `GET /api/v1/platform/stats`, a user route on the token-tenant chain.
  - sdk-go still carries the old platform-mode calls
    (`/api/v1/platform/register`, `lease`, `poll`, `jobs/{id}/...`), which
    sensor v0.6.x uses and the API no longer serves.
- **The admin console shares the user origin.**
  - The admin session cookie is limited by `Path` to the admin API path.
    Cookie `Path` is not an isolation boundary: script on the same origin
    can send requests to that path, and the browser attaches the cookie.
  - The only real separation between the console and a cross-site-scripting
    bug in the tenant app is a separate origin.
  - OWASP's REST cheat sheet says to expose management endpoints "via
    different HTTP ports or hosts".

#### P3. The contract is incomplete and drifts (consumers)

- **Coverage.** 472 operations are documented and 475 are not:
  - 433 in `api/openapi/undocumented-routes.txt`;
  - 22 sensor v2, documented in their own 3.1 file;
  - 15 SCIM;
  - 5 ops.

  The frozen baseline keeps the debt from growing, but the URL-tenant
  surface (42 of 47) and the inbound webhooks (0 of 2) are effectively
  invisible to the generated client.
- **Parameter-name drift.** 14 documented operations name their parameters
  differently in the spec and in the router:
  - `{repository_id}` vs `{repositoryId}` (7 branch routes);
  - `{tool_id}` vs `{toolId}` (5);
  - `{cve_id}` vs `{cveId}`;
  - `{id}` vs `{assetId}`.

  `openapicontract` normalises every parameter to `{}` ("a rename is not a
  contract change"), so check A/B/C cannot see it. Generated clients use the
  spec's names.
- **Phantom web calls.** About 33 web call targets name a path with no route
  at any method.
  - Some are live code paths:
    - `POST /auth/resend-verification`
    - `POST /integrations/{id}/send`
    - `POST /tools/{id}/check-version`
    - `POST /threat-intel/enrich/bulk` (the route is
      `POST /threat-intel/enrich`)
    - `PATCH /relationships/suggestions/update-type`
    - `GET /tenant-tools/stats/executions/{id}`
  - The rest are in `security-hooks.ts` hooks that no component imports:
    `/runners`, `/remediation`, `/analytics/*`, `/reports/generate`,
    `/scans/start`, `/scans/{id}/stop`, `/scans/{id}/results`,
    `/pentest/reports` and `/pentest/retests`.
  - There is no check that the web's endpoint builders name real routes.
- **Documented paths that do not exist.**
  - `api/docs/how-to/configure-siem.md` and `architecture/overview.md`
    document `/api/v1/telemetry-events`; the route is
    `/api/v1/agent/telemetry-events`.
  - The public docs site documents `/api/v1/ingest/ctis` (getting started)
    and `/api/v1/platform-agent/*` and `/api/v1/platform-jobs`
    (API reference). None of these exist.
  - The CI-ingest guide correctly documents
    `/api/v1/agent/ingest/{ctis,sarif,recon,check}`. So **CI pipelines are
    external callers of protocol v1**, not just sensors (see §6.2 P4).
- **Two OpenAPI documents in two versions** (Swagger 2.0 and OpenAPI 3.1).
  Swagger 2.0 has one `basePath`, so it cannot describe the planes or the
  separate hosts.

#### P4. Secrets in the URL path (security)

- Six routes carry the invitation bearer token in the path:
  `/api/v1/invitations/{token}`, `/preview`, `/accept`,
  `/accept-with-refresh` and `/decline`.
- URL paths are written to access logs. The gateway logs `request>uri` and
  redacts only the `ticket` query parameter. OWASP's REST cheat sheet says
  secrets must not appear in URLs.
- api#552 limited who can *see* invitation tokens. The path still writes the
  token to every log on its way through.

#### P5. No rule for actions, bulk and synonyms (consumers, reviewers)

- **211 routes** end in or contain a verb-like segment (80 distinct verbs).
  They fall into these shapes:

  | Shape | Routes | Assessment |
  |---|---:|---|
  | `POST /{collection}/{id}/{verb}` | 106 | the de-facto custom method; fine |
  | collection-level verbs | 71 | e.g. `POST /groups/sync`, `POST /scans/quick` |
  | verb in mid-path | 13 | |
  | `GET` on a verb segment | 21 | e.g. `GET /threat-intel/sync` (status) beside `POST /threat-intel/sync` (action); `GET /me/permissions/sync`; `GET /audit-logs/verify`; `GET /components/export` |
  | `PATCH`/`DELETE` on a verb segment | 10 | `PATCH /findings/{id}/classify`, `PATCH /notifications/{id}/read`, `PATCH /reports/schedules/{id}/toggle`, `DELETE /findings/{id}/link-ticket` |

- **Synonyms:** `activate`/`deactivate` (11/8) and `enable`/`disable` (6/8)
  mean the same thing on different resources.
- **Bulk operations come in four shapes:**
  - `POST /findings/bulk/status`
  - `PATCH`/`DELETE /asset-groups/bulk`
  - `POST /scope/targets/bulk/delete`
  - `POST /findings/ai-triage/bulk`
- **Alternate keys are expressed as path segments:**
  - `/vulnerabilities/cve/{cveId}`
  - `/tools/name/{name}`
  - `/capabilities/by-category/{category}`
  - `/audit-logs/user/{id}`
  - `/audit-logs/resource/{type}/{id}`

#### P6. Path parameters (zero wire cost, but they shape generated types)

- **46 distinct parameter names:**
  - `{id}` 394 times;
  - camelCase 139 times across 30 names (`{groupId}` 22, `{tenantId}` 19,
    `{userId}` 13, `{findingId}` 12, ...);
  - snake_case 16 times (`{report_id}`, `{command_id}`, sensor v2 only);
  - single lowercase words 71 times (`{tenant}` 48, `{token}`,
    `{provider}`, `{org}`).
- **9 collections are addressed by more than one parameter name:**

  | Collection | Names used |
  |---|---|
  | tenants | `{tenant}` 48, `{tenantId}` 19 |
  | findings | `{id}` 34, `{findingId}` 10 |
  | assets | `{id}` 27, `{assetId}` 5 |
  | commands | `{id}` 7, `{command_id}` 8 |
  | users | `{id}` 6, `{userId}` 5 |
  | sensors | `{id}` 13, `{sensorId}` 2 |
  | invitations | `{invitationId}`, `{token}` |
  | permission-sets | `{id}`, `{permissionSetId}` |
  | controls | `{id}`, `{mappingId}` |

- **26 nested paths mix `{id}` with another parameter.**

Parameter names never travel on the wire. Renaming one is a free change for
callers, but it changes the path keys in `web/src/lib/api/generated/api.types.ts`.

#### P7. Query and response conventions (consumers)

- **Query parameters are consistently snake_case:** 197 distinct, and the
  only camelCase one is `startIndex`, which SCIM mandates.
- **Pagination has five dialects**, counted by handler reads:
  - `page`/`per_page`: 86/79
  - `limit`: 23
  - `offset`: 15
  - `page_size`: 7
  - `cursor`: 1
- **Sorting has four:**
  - `sort`: 11
  - `sort_by` + `sort_order`: 4
  - `order`: 4
  - `order_by`: 1
- **Errors use two formats:**
  - The user plane returns
    `{error, code, message, details, request_id}` (`pkg/apierror`).
  - Sensor v2 returns RFC 9457 `application/problem+json`.
- **Updates use `PUT` 78 times and `PATCH` 37 times.** There is no rule for
  which.

#### P8. Naming leftovers (cosmetic)

- **"agent"** is in 35 paths: the 23 protocol v1 routes and the 12 `/agents`
  redirects. Both sets are frozen and go away at the v1 sunset (RFC-029
  §5.4). Renaming them now would break deployed sensors for a word.
  - Header `X-Agent-ID` and payload key `agent_preference` belong to the
    same frozen v1 contract.
- **Singular top-level namespaces:**
  - module areas, which are fine: `pentest` 33, `scope` 29, `compliance` 12,
    `threat-intel` 11, `dashboard` 11, `remediation` 9;
  - real singular collections: `secret-store/{id}`,
    `notification-outbox/{id}`, `state-history/{id}`.
- 13 segment names appear in both singular and plural form.
- **Two "self" namespaces**, `/api/v1/me/*` (14) and `/api/v1/users/me/*`
  (14).

#### Not problems (measured)

- **Casing.**
  - Every static path segment is lowercase kebab-case: 0 snake_case and 0
    camelCase segments outside SCIM's spec-mandated `Users`, `Groups`,
    `ResourceTypes`.
  - Query parameters are snake_case.
- **Trailing slashes:** none (chi `Group("/")` routes are normalised).
- **Nesting depth:**
  - The median route has 2 or 3 segments after the version.
  - Only 9 routes have 3 or more parameters or 6 or more segments: admin
    SSO IdPs, sensor v2 segments and module-preset actions.
- **Sensor plane v2:** `/api/v2/sensor` is exclusive. Only the sensor
  authenticator runs there, and user JWTs, cookies and `oct_` keys get a
  401. It is already what a "sensor gateway prefix" should be.

## 4. Standards and peers

### 4.1 What the guides say

| Topic | Google AIP | Microsoft/Azure | Zalando | This RFC |
|---|---|---|---|---|
| Collections | plural (AIP-122) | plural, unabbreviated | plural (rule 134) | plural |
| Segment case | camelCase (AIP-122) | kebab-case preferred (`http-url-casing`) | kebab-case (rule 129) | kebab-case (as today) |
| Query params | snake_case fields | camelCase | snake_case (rule 130) | snake_case (as today) |
| Verbs in paths | custom methods `:verb`, POST (AIP-136) | `:action` | none (rule 141) | `POST /{coll}/{id}/{verb}`, closed vocabulary (§5.4) |
| Nesting | DAG of parents (AIP-121) | — | ≤ 3 sub-resource levels (rule 147) | ≤ 2 parent levels |
| Pagination | `page_size` + opaque `page_token` (AIP-158) | `nextLink` | cursor preferred (rule 160) | page/per_page today; cursor for large or streaming collections |
| Errors | `google.rpc.Status` + `ErrorInfo.reason` UPPER_SNAKE (AIP-193) | `error{code,message,target,details}` | Problem JSON (rule 176) | keep `code` UPPER_SNAKE; add RFC 9457 |
| Versioning | major in path (AIP-185) | `api-version` query, none in path | media type, none in path (rules 114/115) | major in path, per plane (as today) |
| Compatibility | renaming = remove + add; names must not change (AIP-180) | no breaking changes | approval and monitoring before sunset (rules 185–191) | aliases, headers, telemetry, dated removal |
| Deprecation | — | proprietary header | `Deprecation` + `Sunset` (rule 189) | RFC 9745 + RFC 8594 + `Link rel="successor-version"` |

Sources:
- AIP-121/122/131/132/136/158/160/180/185/193 at <https://google.aip.dev/>
- Microsoft Azure REST API Guidelines,
  <https://github.com/microsoft/api-guidelines/blob/vNext/azure/Guidelines.md>
- Zalando RESTful API Guidelines,
  <https://opensource.zalando.com/restful-api-guidelines/>
- RFC 9110 (§9.2.1 safe methods; §9.3.3 POST for resource-specific
  processing)
- RFC 8594 (`Sunset`)
- RFC 9745 (`Deprecation: @<unix seconds>`; `Sunset` must not be earlier)
- RFC 9457 (Problem Details)

### 4.2 Where the guides disagree, and the choice

- **Path versioning.** Azure and Zalando forbid it; Google, GitHub, Stripe and
  CrowdStrike use it.
  - OpenCTEM has a major version in the path on every plane, and its sensors
    already negotiate features through `GET /api/v2/sensor/hello`.
  - Changing the versioning scheme would be churn without benefit. The rule
    is: **major version in the path, per plane; additive changes within a
    major; features negotiated where clients are long-lived (sensors).**
- **Custom-method syntax.** AIP and Azure use `/{id}:verb`.
  - The `:` form is legal in a URI, but our router, the Next.js proxy, WAF
    rule languages and log tooling all treat it as unusual.
  - 106 routes already use `POST /{collection}/{id}/{verb}`.
  - The rule keeps the slash form, with POST only and a closed verb
    vocabulary. It gets AIP-136's semantics (side effects go through POST,
    reads go through GET) without its spelling.

### 4.3 Rules that matter most for a multi-tenant security product

These come from OWASP API Security Top 10 2023 and the REST cheat sheet.

1. **The tenant comes from the credential.** A tenant or owner selector in
   the path is acceptable only when the server verifies the credential
   against that tenant. Inbound webhooks do this: `?tenant=` selects which
   secret to verify the HMAC against. Even then, one tenant model is easier
   to audit than two (API1 BOLA).
2. **Planes are separable by prefix, and optionally by host.** Each plane
   has its own authenticator, body limit, rate limit and WAF policy, and the
   edge can drop a whole plane (API5 BFLA: admin functions on predictable,
   isolatable paths, with role checks behind them). A prefix is not the
   control; the authenticator behind it is.
3. **Inventory and retirement.** Every deprecated path is listed, measured
   and removed on a date. Old and new versions get the same protections
   while both live (API9 Improper Inventory Management).
4. **No secrets in URLs.** Tokens go in headers or the body.
5. **Reads are safe.** A `GET` never changes state (RFC 9110 §9.2.1).

### 4.4 Peers

| Product | Tenancy | Planes and hosts | Versioning |
|---|---|---|---|
| Tenable Vulnerability Management | from the API key (`X-ApiKeys`), never in the path | `cloud.tenable.com`; legacy unversioned roots (`/scans`, `/workbenches/assets`, `POST /vulns/export` → poll `/status`) next to `/api/v3/...` kebab-case with `_verb` actions | mixed; legacy and v3 coexist on one host |
| Tenable Security Center | from the API key | `/rest/<resource>` on-prem | — |
| Qualys | from the account; regional pod host | separate "API server" and "API gateway" hosts per pod | `/api/2.0/fo/asset/host/?action=list`: the verb-in-query anti-pattern, GET or POST interchangeable |
| Rapid7 InsightVM / Insight | from the key; regional host `<region>.api.insight.rapid7.com` | console API `/api/3/...` | major in path |
| GitHub | owner in the path (`/orgs/{org}`, `/repos/{owner}/{repo}`), because one token spans owners | `api.github.com` plus `uploads.github.com` for binary uploads; GHES `/api/v3` | dated header `X-GitHub-Api-Version`, 24-month support, `410` after |
| ProjectDiscovery Cloud | key plus team header `X-Team-Id` | `api.projectdiscovery.io/v1/...` | major in path |
| CrowdStrike Falcon | from the OAuth client | regional API hosts | version **per endpoint** at the end (`/devices/queries/devices/v1`) |
| Azure ARM | subscription in the path | control plane `management.azure.com`, data plane per-resource hosts; RBAC differs per plane | `api-version` query |

The pattern for security vendors is a tenant from the credential, a region
or plane in the **host**, and major versions that coexist for years.
OpenCTEM's token-tenant model already matches it. The `/tenants/{tenant}`
model is the outlier.

## 5. Options

Cost figures come from §3:
- web call sites: 1,159 in total; 62 under `/tenants/{t}`; 39 under
  `/admin`;
- sensors: every deployed sensor speaks v1 and/or v2 through sdk-go v0.15
  or v0.16.

### Option A: keep everything, fix the worst

Changes:
- move the invitation token into the body;
- add the SSO gate to the URL-tenant chain;
- fix the 14 spec parameter drifts and the ~33 phantom web calls;
- write a style guide.

| | |
|---|---|
| Cost | about 10 routes, a few dozen web lines, no sensor change |
| Risk | lowest |
| Security benefit | closes P4 and the most direct P1 gap; does nothing for plane separation (P2) or the second tenant model; RFC-040 keeps a hand-maintained route list |
| Verdict | necessary but not sufficient; it is the first step of B′ |

### Option B: new top-level prefix per plane (the owner's example)

Prefixes:
- `/admin/api/v1/...` for platform admin;
- `/sensor/v2/...` for the sensor gateway;
- `/hooks/...` for inbound;
- `/api/v1/...` for user and tenant routes.

Every moved route gets an alias with `Deprecation`/`Sunset`.

| | |
|---|---|
| Cost | admin: 54 routes, 39 web call sites, admin CLI. Sensor: 46 routes, **an SDK release and every sensor upgraded**, a new negotiation (sdk-go hardcodes every path and only the host is configurable; `hello` negotiates features, not paths), install snippets, docs, helm. Hooks: 2 routes plus every customer's Jira/GitHub webhook configuration |
| Risk | medium to high, concentrated on the sensor fleet, the one consumer that cannot be redeployed with the platform |
| Security benefit | prefix-level plane separation, but `/api/v2/sensor` and `/api/v1/admin` **already are** exclusive prefixes. Moving them adds nothing an edge rule cannot match today. The benefit of the admin move (origin isolation) comes from a separate **host**, not a new path |
| Verdict | right goal, wrong lever for sensors and admin |

### Option B′ (recommended): plane table on the exclusive prefixes, host split, move only what leaks

The plane table, in code (`routes/plane`) and checked by CI:

| Plane | Canonical prefix | Optional own host | Authenticator | Edge policy |
|---|---|---|---|---|
| user | `/api/v1/` (everything not below) | app host | session / `oct_` | WAF app rules, per-user read limit |
| self | `/api/v1/me/` | app host | session | — |
| auth | `/api/v1/auth/` | app host | none / rate-limited | strict per-IP limits |
| admin | `/api/v1/admin/` | `OPENCTEM_ADMIN_HOSTNAME` (new) | admin session / `X-Admin-API-Key` | IP allowlist, MFA, can be dropped at the edge |
| sensor | `/api/v2/sensor/` (+ `/api/v1/agent/` until v1 removal) | `OPENCTEM_SENSOR_HOSTNAME` (RFC-040) | sensor key / RFC 9421 | sensor gateway, body limits per route |
| inbound | `/hooks/` (new; legacy `/api/v1/webhooks/incoming/`) | app or sensor host | HMAC per tenant | small bodies, per-provider limits |
| scim | `/scim/v2/` | app host | SCIM bearer | — |
| mcp | `/api/v1/mcp` | app host | `oct_` | per-key limits |
| ops | `/health`, `/ready`, `/metrics` | internal | none / metrics bearer | `/health` public; `/metrics` and `/ready` already 404 at the edge |

The moves, each with an alias, headers, a metric and a removal date (§6):

1. **Invitation token out of the path** (P4).
   - `POST /api/v1/invitations/lookup`, `/accept`, `/decline` and
     `/accept-with-refresh`, each with `{ "token": ... }` in the body.
   - The old `/{token}` routes stay as aliases until removal.
2. **Sensor routes outside the sensor prefix become v2 features** (P2).
   - `POST /api/v2/sensor/evidence` (feature `evidence`) replaces
     `/api/v1/validation/evidence`.
   - `POST /api/v2/sensor/credentials` (feature `credentials`) replaces
     `/api/v1/agent/credentials/ingest`. Each realm gets its own handler
     wrapper, so the user and sensor realms no longer share a mount.
   - The SDK switches only when `hello` lists the feature (RFC-029 §6.1). The
     old paths follow the v1 sunset.
3. **`/api/v1/tenants/{tenant}/*` becomes `/api/v1/organization/*`**
   (P1; name to be decided, D2). This is a token-tenant singleton with the
   full chain:
   - `GET`/`PATCH /organization`
   - `/organization/members`
   - `/organization/invitations`
   - `/organization/settings/{section}`

   `GET /api/v1/tenants` (my organizations) moves to `/api/v1/me/tenants`.
   `POST /api/v1/tenants` (create) stays.

   These routes are reachable only by user sessions: `oct_` keys never had
   this chain. Their only consumer is the web, which ships in the same tag
   as the API, so the alias window can be short.
4. **One self namespace** (P8): `/api/v1/users/me/*` moves to
   `/api/v1/me/*` (14 routes).
5. **Inbound webhooks** move to `/hooks/{provider}` (`/hooks/jira`,
   `/hooks/github`), if D5 is accepted.
6. **Edge:**
   - The Caddyfile routes by the plane table, not by credential sniffing.
   - The stale `/api/v1/platform/*` rule is removed.
   - Admin and sensor planes can be bound to their own hostnames. When a
     plane hostname is configured, that plane's paths answer `404` on the
     other hosts.

Not moved:
- `/api/v2/sensor` stays.
- `/api/v1/admin` stays (D3).
- `/api/v1/agent/*` and `/api/v1/agents/*` die on the RFC-029 schedule
  instead of being renamed.

Converged under the lint, with no big bang:
- parameter names;
- custom-method spellings;
- bulk shape;
- pagination and sort for new routes;
- spec/route parameter-name equality.

| | |
|---|---|
| Cost | about 70 routes move: 6 invitation, 2 sensor, 47 URL-tenant, 14 self, 2 hooks. Web: about 90 call sites (62 tenant, 21 `/users/me`, 4 invitation, 2 evidence), mostly `endpoints.ts` builders. SDK: two optional features. Docs: the API docs, install docs for hooks, helm/Caddy rules. Lint: one new package plus a baseline |
| Risk | low to medium. The sensor fleet is touched only through negotiated, optional features. Web routes move atomically with the release. External callers are affected only by the hooks move (D5) and the invitation lookup (emails carry web links, not API paths) |
| Security benefit | one tenant model; a route table RFC-040 can mount without a hand list; per-plane WAF, rate-limit and body-limit rules at the edge; admin on its own origin; no tokens in logs; old paths measured and retired (API9) |

### Option C: full v2 redesign

Rename all 947 operations under `/api/v2`, AIP-style, run both versions side
by side, and migrate the web, MCP, integrations, docs, SDK and sensors.

| | |
|---|---|
| Cost | 947 operations; 1,159 web call sites; regenerating every type; rewriting the API docs; MCP tool surface; a dual-stack period of at least 6–12 months during which every security fix lands twice |
| Risk | high. Two live versions double the surface (OWASP API9). AIP-180 counts a rename as remove plus add, so every documented caller breaks at removal. The owner's EASM priority (RFC-036) would wait behind it |
| Security benefit | the same as B′, and it arrives later |
| Verdict | not recommended. A v2 is justified when **semantics** change (resource model, auth model), not spelling. Spelling converges under the lint at near-zero cost |

### Recommendation

**B′.** It fixes every item that can cause a security defect (P1, P2, P4)
and the consumer-visible drift (P3). It gives RFC-040 its route table and
leaves deployed sensors alone. Option A is its first phase. Option C's only
extra deliverable is cosmetic, and the lint delivers that incrementally.

## 6. Migration and compatibility

### 6.1 Mechanism

The existing protocol v1 deprecation, generalised:

- **`middleware.Deprecated(successor, deprecatedAt, sunsetAt)`** sets
  `Deprecation: @<unix>` (RFC 9745), `Sunset: <IMF-fixdate>` (RFC 8594) and
  `Link: <successor>; rel="successor-version"` on every response, errors
  included. This is `legacyv1.DeprecatedRoute`, made generic.
  - The headers are set before the handler runs.
  - Bodies and status codes are unchanged.
  - `Sunset` must not be earlier than `Deprecation`, and the lint checks it.
- **Telemetry:**
  `deprecated_route_requests_total{plane, route, client}` counts every call,
  where `client` is one of `web`, `oct_key`, `sensor`, `admin_cli` or
  `other`. It comes from the authenticator that ran, never from
  `User-Agent`.
  - It is shown on the admin console's platform page next to the existing
    `sensor_protocol_requests_total{protocol="1"}` and
    `deprecated_management_path_requests_total`.
  - It is logged once per caller per day with the route and the caller's
    key ID, never the token.
- **Aliases share the handler and the full chain of the new route**, so an
  old path is never weaker than its successor. The lint checks this (§7,
  R10).
- **OpenAPI** marks old operations `deprecated: true` with an
  `x-sunset: <date>`. The web's generated types then show the deprecation at
  compile time.
- **Removal** replaces the alias with
  `410 Gone` + `application/problem+json` naming the successor for one
  release, then deletes it.
- **Sensors** change only through `GET /api/v2/sensor/hello` features. The
  SDK keeps the old path whenever the feature is absent.

### 6.2 Timeline

The release train runs every other Monday (RFC-037), and dates are
"earliest". Removal also requires the telemetry criterion:

- 30 days with no call;
- or, for web-only routes, the release that stopped calling them plus 30
  days for stale browser tabs.

| Phase | When | What | Consumers touched |
|---|---|---|---|
| P0 | next train (2026-10-12) | RFC accepted; `routes/plane`; `tools/lint/routestyle` blocking with a frozen baseline; `Deprecated()` middleware and metric; spec/route parameter-name equality (check D); web phantom-call check; conventions doc | none |
| P1 | trains of 2026-10-26 and 2026-11-09 | invitation token to body (aliases, `Deprecation` now); SSO gate decision for the URL-tenant chain (fix if the test confirms the gap); Caddy routes by plane table; stale `/platform/*` rule removed; optional admin hostname; fix the live phantom web calls | web, gateway |
| P2 | 2026-11 → 2026-12 | `/api/v1/organization/*` and `/api/v1/me/*` added, web moved in the same release, old paths aliased with `Deprecation`; sdk-go `evidence` and `credentials` v2 features; `/hooks/{provider}` (if D5) | web, SDK (optional), webhook docs |
| P3 | 2027-01-15 | **removal** of the URL-tenant, `/users/me` and invitation-path aliases (web-only; one quarter after deprecation, telemetry at zero) | none if telemetry is zero |
| P4 | 2027-04-01 + telemetry | protocol v1 removal per RFC-029 §5.4 (`/api/v1/agent/*`, the `/agents` 308s, `/api/v1/validation/evidence`); `/api/v1/webhooks/incoming/*` removed after 6 months of `Sunset` **and** 30 days of zero calls (customers re-point their Jira/GitHub webhooks) | sensors on v1 only (by then RFC-032 enrollment and protocol v2 are the norm), webhook owners. **Precondition:** v1 ingest routes without a v2 successor (`ingest/sarif`, `ingest/recon`, `ingest/scan`, `scans`, `telemetry-events`), which CI pipelines and the docs use, must first gain v2 features (RFC-029 results media types), or they stay outside the v1 removal |

Parameter-name normalisation (P6) can happen in any release, area by area,
because it does not change the wire. Each batch regenerates the spec and the
web types in the same PR, and the baseline shrinks with it.

### 6.3 Interplay with other RFCs

- **RFC-040:** the sensor gateway mounts plane `sensor` from
  `routes/plane` and nothing else. Its route table *is* the plane table,
  checked by the lint.
- **RFC-032:** `POST /api/v2/sensor/enroll` is in the sensor plane by
  construction. The new credentials (`octs_` sensor key, `octe_` enrollment
  token, `oct_` user/MCP key) map 1:1 onto planes:
  - `octs_` and `octe_` are accepted only on the sensor plane;
  - `oct_` only on the user and MCP planes.

  The authenticator refuses a prefix from the wrong plane before any lookup.
  This gives the edge and the logs a second, credential-side plane check.
- **RFC-029:** unchanged. v1 removal criteria and dates stand. New sensor
  routes are only ever v2 features.
- **RFC-022:** the admin console can live on its own origin
  (`OPENCTEM_ADMIN_HOSTNAME`). The admin session cookie then becomes a host
  cookie (`__Host-admin_session`) instead of a path-scoped one.

## 7. CI guard: `tools/lint/routestyle`

The guard is a Go test package next to `tools/lint/openapicontract`, and it
reuses that package's AST walk (`openapicontract.Routes`, extended to return
the group and route middleware). It runs in `api-ci` with the other linters.

| Rule | Check |
|---|---|
| R1 plane | Every route matches exactly one plane in `routes/plane`. The authenticator in its chain matches the plane: sensor authenticator ⇔ sensor plane; `AdminAuthMiddleware` ⇔ admin plane; tenant chains only on the user, self or organization planes. |
| R2 segments | Static segments match `^[a-z][a-z0-9-]*$` (SCIM exempt by plane). |
| R3 params | Parameter names match `^[a-z][a-z0-9_]*$`. Identifiers end in `_id`. One collection uses one parameter name everywhere. Route and spec names are equal. |
| R4 collections | The segment before a parameter is plural, or is on the allowlist of singletons and alternate keys. |
| R5 actions | A verb segment (closed vocabulary, §5.4 of the conventions) appears only as the last segment and only with `POST`. `GET` is never on a verb. Synonyms are refused, for example `activate` → use `enable`. |
| R6 tenancy | No `{tenant}`, `{tenant_id}` or `{org}` parameter outside the admin, auth and inbound planes. |
| R7 secrets | No parameter named `token`, `secret`, `password` or `key` (the last unless it is on the allowlist). |
| R8 depth | At most 2 parent collections (3 parameters) and 6 segments after the version. |
| R9 closed prefixes | No new route under `/api/v1/agent/`, `/api/v1/agents/`, `/api/v1/tenants/{…}/`, `/api/v1/users/me/` or `/api/v1/webhooks/incoming/`. |
| R10 deprecation | A route under a closed prefix carries `Deprecated(...)`, its successor exists, and `Sunset` ≥ `Deprecation`. |

**Baseline.** `api/openapi/route-style-baseline.txt` holds today's
violations, one `RULE METHOD /path` per line. It works like
`undocumented-routes.txt`:

- shrink-only;
- an entry that no longer matches a route fails the test, so the file cannot
  rot;
- a new violation fails CI unless it is added to the baseline in the same
  PR, where a reviewer sees it.

**Web side.** A vitest test checks that every builder in
`web/src/lib/api/endpoints.ts` produces a path present in the generated
spec, plus the sensor and SCIM documents. This closes P3's phantom calls.

**Spec side.** Check D in `openapicontract`: for each documented operation,
the spec's parameter names equal the router's. Unlike checks A/B/C, it does
not normalise names.

## 8. Decisions for the owner

**Approved by the owner on 2026-10-03: every decision as recommended below.**
Two notes from the approval:

- D5: the old `/api/v1/webhooks/incoming/*` aliases stay until the
  deprecation metric reads zero.
- D11: the lint is blocking from day one, with a shrinking baseline.

| # | Decision | Recommendation (approved) |
|---|---|---|
| D1 | Which option: A, B, **B′** or C | **B′** (A is its phase P0/P1) |
| D2 | Name of the token-scoped singleton that replaces `/tenants/{tenant}` | `/api/v1/organization` (the UI and RFC-022 say "organization"); alternative `/api/v1/tenant` |
| D3 | Admin plane: keep `/api/v1/admin` plus an optional own host, or move to `/admin/api/v1` | keep the path, add `OPENCTEM_ADMIN_HOSTNAME`; the host gives origin isolation, the path move gives nothing an edge rule lacks |
| D4 | Sensor plane: keep `/api/v2/sensor` as canonical; new sensor routes only as negotiated v2 features; no `/sensor/v2` | yes |
| D5 | Inbound webhooks: move to `/hooks/{provider}` (customers re-point webhooks within 6 months) or keep `/api/v1/webhooks/incoming/*` | move; it is the only unauthenticated, Internet-facing machine plane, and a top-level prefix lets the edge give it its own body and rate limits |
| D6 | Path parameter convention `{snake_case}` with `_id` (matches JSON and sensor v2), normalised area by area (no wire change; regenerates web types) | yes |
| D7 | Custom-method spelling: `POST /{coll}/{id}/{verb}` (house form) vs AIP `:verb` | slash form |
| D8 | Pagination for new list routes: `page`/`per_page` with `{data,total,page,per_page,total_pages}`, plus `cursor`/`next_cursor` for exports and unbounded collections | yes |
| D9 | Errors: keep the user-plane envelope; serve RFC 9457 when `Accept: application/problem+json`, and by default on new planes (inbound, organization) | yes |
| D10 | Removal dates: web-only aliases 2027-01-15; external aliases ≥ 6 months after `Deprecation` and 30 days of zero use; sensor v1 per RFC-029 | yes |
| D11 | Lint from day one as **blocking** with a frozen baseline, or report-only for a cycle | blocking (the openapicontract precedent worked) |
| D12 | The 158 user and admin routes the web never calls: audit them for API-key/MCP use before any removal (separate issue) | separate issue, no removal in this RFC |

## 9. Follow-ups this RFC files but does not do

- **Verify the SSO-enforcement gap** on the URL-tenant chain (P1) with an
  integration test. Fix it in P1 if confirmed.
- **Fix the live phantom web calls** (§3.2 P3) or delete the calls.
- **Remove dead hook modules** (`security-hooks.ts` sections for runners,
  remediation, analytics and reports) after a usage check.
- **Document the 47 URL-tenant routes** as they move (they will be
  documented as `/organization`), and the inbound webhooks.

## 10. Implementation tracking

| Phase | Item | PR |
|---|---|---|
| P1 (security first) | URL-tenant chain runs the SSO-enforcement gate for the organization in the URL, and the read rate limit | #874 |
| P0 | `routes/plane` plane table | #876 |
| P0 | `tools/lint/routestyle`, blocking, shrink-only baseline (362 violations frozen) | #876 |
| P0 | `openapicontract` check D (spec and router parameter names equal) | — |
| P0 | web check: every `endpoints.ts` builder targets a real route | — |
| P0 | `Deprecated()` middleware + `deprecated_route_requests_total` | — |
| P1 | live phantom web calls fixed or removed | — |
| P1 | gateway routes by the plane table: `planes.caddy` generated from `routes/plane` (`PlaneEdges`, `EdgeOverrides`), drift test in CI, stale `/api/v1/platform/*` rule removed, smoke test covers every plane | this PR |
