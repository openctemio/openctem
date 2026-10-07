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
   are no longer created; a finding on one moves to the origin), normalises
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
