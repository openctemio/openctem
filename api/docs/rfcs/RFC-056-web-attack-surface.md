# RFC-056: Web attack surface (origins, endpoints, parameters, path patterns)

| | |
|---|---|
| Status | Implemented (decisions WS1–WS14, 2026-10-07; W-OC1–W-OC8) |
| Scope | api (`pkg/domain/webendpoint`, `internal/app/ingest`, `internal/infra/postgres`, scope, dispatch, handlers, migrations), web (Web surface), ctis 1.6 (`endpoints[]`, `finding.web`, `weburl`), sdk-go (`webscope`) |
| Architecture | [web-surface.md](../architecture/web-surface.md) |
| Related | RFC-042 (asset inventory v2: the `web_endpoint` class), RFC-043 (finding identity: the DAST recipe), RFC-054 (scope model), RFC-055 (tool contract: the `endpoint` port, CTIS 1.6, `web_scope`) |

## 1. Summary

A crawl used to create one asset per URL (`service/discovered_url`), with no
link to its web service, its parameters dropped and its query values kept in
the received report. Path scope rules never reached a sensor and never
matched a URL. This RFC gives the web surface its own model:

1. **Origins** (scheme, host, port) stay assets: the existing `http_service`
   asset. Web applications stay `application/website|api` assets.
2. **Endpoints** (a method and a path template) and **parameters** (a
   location and a name, never a value) live in a tenant-scoped
   **sub-inventory under the origin asset**, like the ports of a host
   (`asset_services`). One crawl of one site writes rows there, never
   thousands of assets, attribution records or graph nodes.
3. A computed **path pattern** key (the host-less template hash) answers
   "where does `/actuator/env` exist?" across the origins of one tenant. It
   is never compared across tenants. A **platform-curated** catalog of
   sensitive paths labels them; it is never learned from tenant data.
4. **Path-aware scope**: scope entries and exclusions carry a host pattern, a
   segment-aware path prefix and methods. The platform enforces them at
   dispatch and at ingest, the signed job carries them (`web_scope`), and the
   SDK enforces them on the sensor.
5. **Values are never stored**: parameter values, query values, user info and
   fragments are dropped by the producer and again by the platform; token-like
   path segments are templated before storage.

## 2. Decisions (2026-10-07)

| # | Decision |
|---|---|
| WS1 | Endpoints live in sub-inventory tables under the origin asset. |
| WS2 | `discovered_url` assets are retired: existing rows are migrated into endpoints, then deleted (one-step upgrade note). |
| WS3 | The origin is the existing `service/http` asset. |
| WS4 | Path patterns are a computed key plus a view; a state table only when users attach state; never a cross-tenant dataset. |
| WS5 | The sensitive-path catalog is platform-curated, embedded, versioned data. |
| WS6 | One templating library (`ctis/weburl`); the finding identity recipe keeps its own versioned rule set, so finding keys never churn. |
| WS7 | Static files (style sheets, images, fonts, media) are counted, not stored; JS files are stored as `script`, capped. |
| WS8 | Parameter fuzzing is the T2 mode of `vuln.templates` / `dast.web`, not a new capability. |
| WS9 | The inert `path` exclusion type is replaced by `url` entries/exclusions with a host pattern, a path prefix and methods; live rows are migrated. |
| WS10 | An endpoint under an excluded prefix that a non-requesting source reports (a link on another page, JS, sitemap, a spec) is stored as **excluded, untested**, never targeted or alerted on. |
| WS11 | Parameter values are never stored; one masked example path per endpoint. |
| WS12 | Write methods on production need T2, the environment policy and a method allow-listed on the scope entry; default deny. |
| WS13 | Spec import covers OpenAPI, GraphQL, Postman and HAR through one importer family, upload and CI push. |
| WS14 | Not seen for 30 days: `gone`; gone for 365 days: purged; events kept 90 days (tenant setting). |

**Excluded paths are not a blind spot** (decided 2026-10-07). An exclusion
stops requests, not knowledge:

- endpoints under an excluded path are still recorded from non-requesting
  sources, with the status *excluded, untested* and the exclusion that holds
  them (rule, reason, author);
- a coverage-gap read counts, per origin and asset, the excluded-untested
  endpoints and flags those on the sensitive-path list; the Web surface view
  and the asset coverage score show it, so "0 findings" is not read as
  "safe";
- exclusions can be method-scoped (block POST/PUT/PATCH/DELETE on `/admin`,
  allow GET), so read-only checks (an exposed admin page, missing auth,
  version disclosure) still run. A new path exclusion defaults to all
  methods; method-scoped is the suggested option for sensitive paths;
- each scope exclusion carries a testing mode: `blocked` (the default),
  `read_only` (GET and HEAD only) or `allowed` (treated as in scope), with an
  optional `allowed_until` after which it reverts to `blocked`. Changing it
  needs the scope-approve permission, step-up and an audit row, and notifies
  the administrators. It only ever re-enables paths on origins that are the
  organization's own in-scope assets (the one authority check of RFC-054:
  scope entry, inventory, proof where required): hosts the exclusion's
  pattern covers that are not the tenant's assets stay refused. Tier
  ceilings, guardrails and the platform deny list still apply, and there is
  no global "allow testing everything" switch (RFC-054 S5). The API contract
  lives in RFC-054.

## 3. Model

### 3.1 Tables

`web_endpoints` (one row per origin, method and template):

| Column | Meaning |
|---|---|
| `tenant_id`, `origin_asset_id` | the tenant and the origin asset; a composite foreign key ties both to `assets(tenant_id, id)` |
| `method`, `path_template` | `GET`…`ANY`; the template (`/api/v1/users/{int}/orders`) |
| `template_hash` | `ctis/weburl.PathHash(method, template)`: the dedup key within the origin |
| `path_hash` | sha256 of the template alone: the path-pattern key within the tenant |
| `kind`, `sources` | page, api, script, form, graphql, websocket, other; how it was found (crawl, js, sitemap, robots, spec, har, archive, dast, probe) |
| `example_path` | one concrete path, token-like segments masked, never a query |
| `last_status`, `content_type`, `auth_state` | the last response seen (`auth_state` none, required, redirect_login, unknown) |
| `technologies`, `labels`, `catalog_key` | technology names; labels; the sensitive-path catalog id when matched |
| `response_sig`, `last_changed_at` | hash of status, content type and auth state; stamped when it changes (the incremental selector reads it) |
| `state`, `in_scope` | active, gone, ignored; `in_scope = false` is *excluded, untested* |
| `first_seen_at`, `last_seen_at`, `last_run_id`, `last_sensor_id`, `last_tool` | provenance, from the server-side binding of the report, never from its body |

`web_endpoint_params` (one row per endpoint, location and name): `location`
(query, path, header, cookie, form, json, multipart, graphql_arg), `name`,
`type_hint`, `required`, `risk_hints` (ssrf_candidate, redirect,
idor_candidate, file_path, from the name), `sensitive` (credential, pii,
financial, from the name), `sources`, first and last seen. **There is no value
column.**

### 3.2 Normalisation

The platform recomputes everything a report says with `ctis/weburl` (strict
parse, origin normalisation, path normalisation, typed variables `{int}`,
`{uuid}`, `{date}`, `{email}`, `{hex}`, `{token}`, `{id}`). A report's own
template is a hint and is ignored, so a hostile sensor cannot choose the row
it writes. Query names become `query` parameters; values are dropped before
anything is stored, logged or quarantined.

### 3.3 Caps

| Cap | Default |
|---|---|
| active endpoints per origin | 5,000 (a new template beyond it is counted, not stored) |
| scripts per origin | 500 |
| parameters per endpoint | 100 |
| endpoints per report | 200,000 (CTIS limit) |
| path, template | 2,048 bytes; parameter name 128 bytes |

A re-sighting rewrites a row at most hourly unless something changed.

## 4. Ingest

1. The output binding (RFC-040, RFC-055) admits `endpoints[]` only from a
   tool whose stage reports endpoints (`crawl.web`, `dast.web`) and, when the
   tool declares a contract, whose `produces` names `endpoint`.
2. Legacy `discovered_url` assets are folded into endpoints and no longer
   created; a finding on one moves to its origin.
3. Each endpoint's origin is an `http_service` asset of the report, or one is
   added to the report, so it passes the same scope, exclusion, identity and
   binding checks as any asset. A command-bound report writes endpoints only
   under origins its targets cover; endpoints land only under an origin asset
   the report may change (created by it, covered by its command, inside the
   uploading actor's data scope) and only if that asset is an `http_service`.
4. Endpoints under a path exclusion are stored with `in_scope = false`.
5. The rows are upserted per origin in one transaction, serialised by an
   advisory lock so concurrent reports cannot pass the caps.

A crawl now hands the chained stage its origin asset, not one asset per URL.

## 5. Scope for paths and methods

Exclusion shape: an exclusion of type `path` with `pattern` = host pattern,
`path_prefix` and `methods` (WS9: the old one-string `path` type is replaced
by this rule and its rows migrated; the API contract is in RFC-054 §6.2).
Scope entries with a path prefix (a grant limited to a path, for web tools
only) follow in a later change.

- The path match is a segment-aware prefix (`/admin/debug` matches itself
  and `/admin/debug/x`, not `/admin/debugger`); no regular expression.
- An exclusion without a host (`*` host) applies on every host in scope.
- An entry with a path grants web tools only that prefix and never grants
  the host to network tools.
- Enforced at platform dispatch (endpoint and URL targets under an excluded
  prefix are dropped and audited), carried in the signed job as `web_scope`
  (hosts, path prefixes, deny paths, methods; RFC-055 §6.1), enforced by the
  SDK, and re-checked at ingest.

## 6. API

Strict REST, the list-query contract (RFC-048); `include=` only for
low-sensitivity counters.

| Method + path | Purpose | Permission |
|---|---|---|
| `GET /api/v1/web-endpoints` | list (filters, pagination) | `assets:read` + data scope |
| `GET /api/v1/web-endpoints/stats` | counts by method, kind, auth, state | `assets:read` + data scope |
| `GET /api/v1/web-endpoints/{id}` | detail | `assets:read` + data scope |
| `GET /api/v1/web-endpoints/{id}/parameters` | parameters | `assets:read` + data scope |
| `PATCH /api/v1/web-endpoints/{id}` | state (active, ignored), labels | `assets:write`, audited |
| `GET /api/v1/assets/{id}/web-endpoints` | endpoints of one origin | `assets:read` + data scope |
| `GET /api/v1/web-path-patterns`, `…/{hash}/web-endpoints` | the path-pattern view | `assets:read`, counts scope-filtered |
| `GET /api/v1/web-endpoint-events` | change feed | `assets:read` + data scope |
| `POST /api/v1/api-specs` and sub-resources | spec store and drift | `assets:write` |

Every by-id route answers 404 for another tenant's id and for an id outside
the caller's data scope.

## 7. Security

| Threat | Control |
|---|---|
| Secrets in URLs (`?token=`, signed paths, reset links) stored or shown | query values dropped by producer and platform; token-like segments templated; `example_path` masked; no value column |
| A report attaching endpoints to another tenant's or another asset's origin | origin resolved from the report's own assets after binding; command targets must cover it; composite tenant foreign keys |
| Crawler traps, giant reports | caps per origin, script and parameter caps, strict parse |
| A tool writing the endpoint inventory it has no business writing | output binding by stage and declared contract |
| Destructive requests | write methods T2 + environment policy + method allow list; method-scoped exclusions |
| Cross-tenant leakage via patterns or the catalog | patterns tenant-scoped; catalog platform data |
| Exclusions read as "safe" | excluded-untested endpoints recorded and counted in the coverage gap |

## 8. Implementation plan

| # | PR | Contents |
|---|---|---|
| W-OC1 | api | tables, ingest of `endpoints[]`, `discovered_url` folded, output binding |
| W-OC2 | api | migrate existing `discovered_url` assets into endpoints, then delete them |
| W-OC3 | api | path- and method-aware scope entries/exclusions, exclusion testing mode, dispatch filter, job `web_scope`, excluded-untested + exclusion reference, coverage gap |
| W-OC4 | api | `/web-endpoints` routes, `/assets/{id}/web-endpoints` |
| W-OC5 | web | Web surface UI (origins, endpoints, path patterns, changes, coverage gap) |
| W-OC6 | api | sensitive-path catalog, `catalog_key`, path-pattern routes |
| W-OC7 | api | `web_endpoint_events`, change feed, retention, incremental selector |
| W-OC8 | api | spec store, upload, drift |
