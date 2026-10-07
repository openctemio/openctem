# Web surface: origins, endpoints and parameters

Design: [RFC-056](../rfcs/RFC-056-web-attack-surface.md).

## Model

```
asset service/http (origin: https://api.example.com)
  └─ web_endpoints        method + path template  (GET /api/v1/users/{int})
       └─ web_endpoint_params   location + name      (query "page", json "/note")
```

- The origin is an ordinary `http_service` asset: scope, ownership, data
  scope, criticality and attribution all live there.
- `web_endpoints` and `web_endpoint_params` are a sub-inventory under it,
  like `asset_services` under a host. Every row carries `tenant_id`; composite
  foreign keys tie an endpoint to an asset of the same tenant and a parameter
  to an endpoint of the same tenant.
- An endpoint is visible exactly when its origin asset is visible to the
  caller (data scope joins `user_accessible_assets` on `origin_asset_id`).
- No column holds a value: parameter names only; one `example_path` with
  token-like segments masked.

## Ingest (`internal/app/ingest/processor_endpoints.go`)

1. `bindOutputTypes` holds a report's `endpoints[]` unless the tool's stage
   reports endpoints (`stage.Stage.Endpoints`: `crawl.web`, `dast.web`) and,
   when the sensor declares a tool contract, its `produces` names `endpoint`.
2. `planEndpoints` folds legacy `discovered_url` assets into endpoints (they
   are no longer created; a finding on one moves to the origin; migration
   001288 converted the stored ones the same way and deleted them), normalises
   every endpoint with `webendpoint.Observe` (ctis/weburl: strict parse,
   template, query names only, masked example), refuses origins a
   command-bound report's targets do not cover, counts static files without
   storing them, and makes each origin an `http_service` asset of the report.
3. The asset pipeline persists the origins (scope, exclusions, identity,
   attribution apply).
4. `recordEndpoints` writes each origin's endpoints only when the persisted
   origin is an `http_service` the report may change
   (`alterScope.allowedAsset`), marking endpoints under a path exclusion
   `in_scope = false`.
5. `WebEndpointRepository.Record` upserts per origin in one transaction under
   an advisory lock, applying the caps (5,000 active endpoints and 500 scripts
   per origin, 100 parameters per endpoint) and rewriting a re-sighted row at
   most hourly unless it changed.

The ingest output reports `endpoints_created`, `endpoints_updated`,
`endpoints_refused`, `endpoints_static`, `endpoints_over_cap` and
`legacy_url_assets_folded`.

## Chaining

A crawl step's outputs are its origin assets, so a chained template scan
runs per origin, not once per crawled URL.

## Path exclusions

An exclusion of type `path` (RFC-054 §6.2) is a web rule: a host pattern, a
segment-aware path prefix, the methods it blocks, and a testing mode
(`blocked`, `read_only`, `allowed` until a deadline) a scope approver sets
with step-up. It is enforced in three places:

| Where | What |
|---|---|
| Dispatch (`scope.Service.ExcludedTargets`) | a URL target under a blocking rule (for GET) is excluded; a host target never is |
| Job (`pipeline.applyWebScope`) | a crawl, template or web application step carries `web_scope`: `deny_paths` for rules that block GET or HEAD, `methods: [GET, HEAD]` when a rule there blocks only other methods; nothing when no rule applies. A failed lookup refuses the step |
| Ingest (`markExcluded`) | an endpoint whose method a rule blocks is stored `in_scope = false` with `exclusion_id`: excluded-untested, visible, never targeted |

`GET /web-endpoints/stats` counts `excluded_untested`, so "0 findings" on an
origin with excluded paths is not read as "safe".

## API

| Route | Permission | Notes |
|---|---|---|
| `GET /api/v1/web-endpoints` | `assets:read` | list query contract (RFC-048, strict: an unknown param is 400); filters `origin_asset_id`, `method`, `kind`, `auth_state`, `state`, `in_scope`, `source`, `label`, `catalog_key`, `path_hash`, `path_template_contains`, `last_status`, `param_count`, seen and changed times; `q` searches the template |
| `GET /api/v1/web-endpoints/stats` | `assets:read` | the same WHERE: counts by method, kind, auth state and state, and `excluded_untested` |
| `GET /api/v1/web-endpoints/{id}` | `assets:read` | 404 for another tenant's id and for an origin outside the caller's data scope |
| `GET /api/v1/web-endpoints/{id}/parameters` | `assets:read` | names, locations, risk hints; never a value |
| `PATCH /api/v1/web-endpoints/{id}` | `assets:write` | `state` (active, ignored) and `labels`; audit-logged on the origin asset |
| `GET /api/v1/assets/{id}/web-endpoints` | `assets:read` | one origin's endpoints; the `/assets/{id}` data-scope guard applies |

The list compiles through `pkg/filterspec` with the caller as the actor, so
the tenant predicate and the caller's data scope (on `origin_asset_id`) are
always in the WHERE, for the list and the stats alike.

## Sensitive paths, patterns, origins and the change feed

- **Catalog** (`pkg/domain/webendpoint/catalog.json`, `GET /web-path-catalog`):
  platform-curated sensitive paths (VCS and configuration files, backups,
  debug and actuator endpoints, admin consoles, infrastructure APIs, API
  descriptions). Ingest stamps `catalog_key` with the most specific entry
  matching the template. Never learned from tenant data.
- **Path patterns** (`GET /web-path-patterns`): the endpoint filter grouped by
  `path_hash` (the template without host or method): how many origins serve
  it, how many answer 2xx, without authentication, or are excluded-untested.
  Within the tenant and the caller's data scope only.
- **Origins** (`GET /web-origins`): per origin asset, endpoints, active,
  excluded-untested, the sensitive ones among those (`excluded_sensitive`),
  sensitive endpoints answering 2xx without authentication
  (`unauth_sensitive`) and new in the last 7 days: the coverage-gap read.
- **Change feed** (`web_endpoint_events`, `GET /web-endpoint-events`):
  appeared, returned, gone, status_changed, auth_changed, param_added,
  written in the same transaction as the change; `detail` holds status codes
  and auth states only.
- **Retention** (`WebSurfaceRetentionController`, hourly): unseen 30 days ->
  gone (with an event), gone 365 days -> deleted with its parameters and
  events, events older than 90 days deleted. Findings are never touched.
- **Incremental scanning:** a template step chained after a crawl with the
  step setting `endpoint_selector: new | changed` takes the URLs of the
  endpoints the crawl found new (or new or changed) in this run instead of
  each origin; an origin with none is skipped as `unchanged`. URLs are built
  from the example path with typed placeholders, never recorded values, and
  pass the same per-hop gate (path exclusions included). The setting is the
  platform's and never reaches the sensor.
