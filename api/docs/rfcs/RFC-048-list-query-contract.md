# RFC-048: List query contract (one filter model, two encodings, one compiler)

> Status: **Accepted** (owner decisions 2026-10-04, §9). Implementation in
> progress (§8).
> Scope: `api/` (`pkg/filterspec`, list/stats/groups/export handlers and
> repositories, OpenAPI generation, `openapicontract`), `web/` (URL codec,
> `buildQueryString`), the gateway access log.
> Related: [RFC-041](RFC-041-api-path-design.md) (paths, casing, pagination,
> deprecation), [RFC-016](RFC-016-mcp-server.md) (MCP tools),
> [RFC-044](RFC-044-issue-definitions-and-findings.md) (future
> `definition_id` keys),
> [architecture/list-query-contract.md](../architecture/list-query-contract.md)
> (how to use it), research 15 (data scope), research 17 (findings analysis
> gaps), research 19 (the full evidence and industry survey behind this RFC).
>
> Owner's question (2026-10-04): should list APIs keep flat query params such
> as `/assets?types=host`, or put every parameter into one filter variable such
> as `/assets?filters={types:[]}`?

## 1. Answer in short

1. **No `?filters={json}`.** It is unreadable in links and logs, cannot be
   typed in our Swagger 2.0 spec, puts whole filter documents (hostnames,
   emails, search terms) into the gateway access log, and fixes none of the
   real problems.
2. **The real problem is many parsers.** Findings alone have five server
   parsers and two SQL WHERE builders with different vocabularies and silent
   failure modes. That is why `asset_tags` is accepted and ignored by the list,
   why `/findings/stats` cannot match the table, and why the web sends a
   `source_id` the server silently drops.
3. **One model, two wire encodings, one compiler:**
   - `GET /{resource}` takes **flat, documented params** built from a
     per-resource field registry: `severity=critical,high&epss_score_gte=0.1&status_not=resolved&q=log4j&sort=-priority_class`.
     The web page URL uses exactly these params.
   - `POST /{resource}/search` takes a **`FilterDocument`** (JSON
     `all`/`any`/`not` with `{field, op, value}` leaves) for OR, nesting and
     large ID lists. It is also the stored form for saved views, exports,
     reports, alerts and campaigns.
   - Both decode into **one AST**. `Compile(spec, registry, actor)` emits
     parameterised SQL and **always** ANDs the tenant and data-scope
     predicates. List, count, stats, groups, export and bulk-by-filter all call
     it, so their counts cannot drift.
4. **Strict validation.** An unknown param, a bad value or an unsortable field
   becomes `400 INVALID_FILTER` with the param or JSON path, after one release
   in which it is logged, counted and answered with a `Deprecation` header.

## 2. Problem (evidence)

The full inventory is research 19 §1. The points that drive the design:

| Problem | Evidence (develop @ `86ef984c`) |
|---|---|
| ~649 hand-written `Query().Get`/`Has` reads of ~230 names; no binding layer | `api/internal/infra/http/handler/*.go` |
| Silent coercion: `parseQueryArray` truncates at 100, `parseQueryBool` treats `yes` as false, a bad date is ignored, an unknown sort field is dropped | `handler/common.go:123-245`, `pkg/pagination/pagination.go:66-70` |
| Findings: list (S1), groups (S2, a second SQL builder), stats (S3, two params), bulk body (S4), campaign JSONB (S5), plus three client vocabularies | `vulnerability_handler.go`, `finding_actions_handler.go`, `finding_group_repository.go`, `remediation_campaign.go`, `web/.../findings/page.tsx`, `use-findings-api.ts`, `mcp_tools.go` |
| `asset_tags` works in groups, ignored by the list; `finding_ids` validates `max=500` after the parser cut it to 100 | `finding_repository.go buildWhereClause` vs `finding_group_repository.go buildFilterWhere` |
| Stats ignore the list filter (findings and assets) | `vulnerability_handler.go` stats, `asset_handler.go` stats |
| One concept, many names: KEV (3), EPSS (2), free text (`search`, `q`, `name`, `filter`), plural vs singular | research 19 §1.3 |
| Spec under-documents handlers (`/findings` documents 12 of ~27 params); nothing checks query-param drift | `api/api/openapi/swagger.yaml` |
| Scope applied per service method where someone remembered it; nothing forces a new aggregate to be scoped | research 15 §1.3 |
| The gateway logs the full query string, so `?q=<email>` reaches the access log | RFC-041 §3.2 P4 |

## 3. Design

### 3.1 Architecture

```
GET /findings?severity=critical,high&epss_score_gte=0.1  ──┐
POST /findings/search {"filter":{…},"sort":[…]}           ──┤
saved_views.filter / campaign.finding_filter (JSONB)       ──┼──► filterspec.ParseValues / ParseDocument ──► Spec (AST)
export / report / alert / MCP tool input                   ──┘                     │ validated against the Registry
                                                                                    ▼
                                            filterspec.Compile(spec, registry, actor)
                                               = tenant AND data scope(actor) AND <leaves>
                                               → (where string, args []any), parameterised only
                                                                                    ▼
                                  list │ count │ stats │ groups │ facets │ export │ bulk-by-filter
```

- **Package `api/pkg/filterspec`**, domain-neutral:
  - `Registry` and `Field{Name, Type, Ops, SQL, Indexed, Permission, Enum, Sortable, MaxValues}`;
  - `ParseValues(url.Values, *Registry, Options) (*Spec, error)` and
    `ParseDocument([]byte, *Registry, Options) (*Spec, error)`;
  - `Compile(*Spec, *Registry, Actor) (Where, error)`;
  - `Spec.Values()` turns the AND-of-leaves subset back into flat params (links).
- **Registries live with the domain** (`vulnerability.FindingFields`,
  `asset.Fields`). A field marked `Sortable` replaces today's
  `AllowedSortFields()` maps.
- **`Actor` is mandatory.** `UserActor(tenant, scope)` takes the scope resolved
  by `datascope.Enforcer.Resolve` (nil only for an unrestricted caller). The
  only way to skip the scope predicate is `SystemActor(tenant, reason)`, and a
  lint allowlists its call sites. The tenant predicate is never skipped.
- **Stored filters run as their viewer or owner.** A saved view runs as the
  viewer; a report, alert or campaign progress count as its owner (closes
  research 15 L-18).

### 3.2 Naming

| Rule | Choice |
|---|---|
| Case | `snake_case` (RFC-041 §4.1) |
| Field name | **singular, equal to the response JSON field**: `severity`, `status`, `cve_id`, `epss_score`, `last_seen_at` |
| Derived fields | explicit registry entries with plain names: `is_in_kev`, `asset_tag`, `asset_criticality`, `related_to`. **No relation paths** (`asset.tags`) |
| Reserved params | `q`, `sort`, `page`, `per_page`, `cursor`, `fields` (later), `view` |
| Forbidden | field names ending in an operator suffix; camelCase; a catch-all `filter`/`filters` param (registry test) |

### 3.3 Arrays

- Canonical: comma-separated in one param, `severity=critical,high`
  (Swagger 2 `collectionFormat: csv`). Repeated keys are also accepted and
  merged.
- Free-text values (`q`, `*_contains`) are single-valued.
- 100 values per list and 200 characters per value (`q` 255). Above a cap is
  **400**, never a silent truncation. `id`-type lists may hold 500 values in
  the POST body only.

### 3.4 Operators (suffixes)

| Operator | GET form | Document `op` | Types |
|---|---|---|---|
| equals / in | `severity=critical,high` | `in`, `eq` | enum, id, string, bool, int |
| not in | `status_not=resolved` | `not_in`, `ne` | enum, id, string, int |
| range | `epss_score_gte=0.1`, `last_seen_at_lt=2026-09-01` | `gte`, `gt`, `lte`, `lt` | number, int, time |
| null | `assigned_to_null=true` | `is_null` | nullable fields |
| contains | `file_path_contains=/src/` | `contains` | declared text fields with a trigram index |
| full text | `q=log4j` | top-level `q` | the resource's search expression |

A field declares the operators it allows; anything else is `INVALID_FILTER`.
Times are RFC 3339 or `YYYY-MM-DD` (midnight UTC; `_lte` on a date means end
of day) or a negative ISO 8601 duration relative to now (`-P30D`, `-PT12H`).
GET semantics are simple: every param is ANDed and a comma list is OR within
one field. OR across fields and nesting exist only in the POST document.

### 3.5 Sort and pagination

- `sort=-priority_class,severity`. `-` is descending; every key must be
  `Sortable`; an unknown key is `INVALID_FILTER`; the server adds the
  resource's primary key as the last tiebreaker. `sort_by`, `sort_order`,
  `order`, `order_by` become deprecated aliases.
- `page`/`per_page` (max 100) for UI lists. `page × per_page > 10,000` is 400
  with a hint to use a cursor or narrow the filter.
- `cursor`/`next_cursor` (opaque, signed, keyset on the sort key + id, bound to
  a hash of the filter) for export, search iteration and MCP.
- Exact `COUNT(*)` until a threshold, then a capped count with
  `total_is_estimate: true`.

### 3.6 The FilterDocument

```jsonc
{
  "v": 1,
  "filter": {
    "all": [
      { "field": "severity", "op": "in", "value": ["critical", "high"] },
      { "field": "status", "op": "not_in", "value": ["resolved", "false_positive"] },
      { "any": [
          { "field": "is_in_kev", "op": "eq", "value": true },
          { "field": "epss_score", "op": "gte", "value": 0.1 }
      ] },
      { "not": { "field": "asset_tag", "op": "in", "value": ["sandbox"] } }
    ]
  },
  "q": "log4j",
  "sort": ["-priority_class", "-epss_score"],
  "page": { "page": 1, "per_page": 100 }
}
```

- A node is exactly one of `all` (array), `any` (array), `not` (node) or a
  leaf `{field, op, value}`.
- **Leaf shorthand:** an object of flat param names
  (`{"severity": ["critical","high"], "epss_score_gte": 0.1}`) at the top of
  `filter` means `all` of those leaves, so a page URL converts to a document
  with no mapping.
- The JSON Schema is `pkg/filterspec/filter_document.schema.json`; per
  resource, `GET /api/v1/meta/filters/{resource}` returns fields, types,
  operators, enums and sortability.
- The same document is the body of `/stats`, `/groups`, `/export`,
  bulk-by-filter, `saved_views.filter` and `remediation_campaigns.finding_filter`.

### 3.7 Limits and errors

| Limit | Value |
|---|---|
| Leaves per document | 50 |
| Nesting depth (`all`/`any`/`not`) | 3 |
| Values per list | 100 (500 for id fields in POST) |
| Value length | 200; `q` 255 |
| POST body | 32 KB, enforced before JSON decoding |
| Statement timeout | 5 s for list/stats/groups, 60 s for export |
| Rate | `…/search` and export in the per-user API bucket; one concurrent export per user |

```json
{
  "error": "INVALID_FILTER",
  "code": "INVALID_FILTER",
  "message": "2 filter errors",
  "details": [
    { "param": "epss_score_gte", "reason": "must be a number", "value": "high" },
    { "path": "filter.all[2].any[0].field", "reason": "unknown field \"is_kev\"" }
  ]
}
```

`details[].value` is echoed only for typed params (never free text) and is
capped at 64 characters.

### 3.8 Rollout mode for unknown params

`Options.UnknownParams` is `warn` or `strict`:

- **`warn`** (one release, from the endpoint's migration): an unknown param is
  ignored as today, but logged (param **name** only, never the value),
  counted in `filter_unknown_param_total{route,param}` (param label capped to
  known-safe characters and length; anything else is `other`), and the
  response carries `Deprecation` plus a `Warning: 299 - "unknown query
  parameter …"` header.
- **`strict`**: `400 INVALID_FILTER`.
- Old param names (`severities`, `exclude_statuses`, `epss_min`, `search`, …)
  are **aliases**: accepted, mapped to the new field, answered with
  `Deprecation`/`Sunset` (RFC 9745 / RFC 8594) and counted in
  `deprecated_query_param_requests_total{route,param,client}`. An alias is
  removed when its counter reads zero for 30 days and 6 months have passed
  (RFC-041 D10).
- Bad values for known params are **always** 400.

### 3.9 Web encoding

- The page URL uses exactly the API params plus page-only state (`tab`,
  `group`, `density`, `view`). One codec (`web/src/lib/filters/url-codec.ts`)
  replaces per-page translation layers. Old page links are rewritten once on
  load through a per-page alias map.
- When a filter does not fit a URL (OR groups, hundreds of IDs) the page uses
  `POST …/search` and offers "Save as view". JSON never goes into a URL.

### 3.10 OpenAPI

- Query params for migrated endpoints are generated from the registry
  (`type: array`, `items.enum`, `collectionFormat: csv`), not hand-written swag
  comments.
- **Drift check:** `openapicontract` check E fails when a param the parser
  accepts (fields × operators, reserved params, aliases) is missing from the
  spec, or the reverse.

## 4. Threat model

| Threat | Actor | Control |
|---|---|---|
| SQL injection through a field, operator, sort key or value | any caller | field, operator and sort key resolved only through the registry; the SQL for a leaf is the registry's constant template; values are always bound parameters. A test compiles every field × operator and asserts the SQL text contains no value bytes and N placeholders for N values. Fuzz targets on both parsers |
| ORM-leak style relation traversal (`created_by__password__startswith`) | any caller | no relation-path syntax; every cross-entity filter is an explicit field whose subquery carries its own tenant and scope predicates |
| Scope widening via a filter (`asset_id=<other user's asset>`) | restricted member | `Compile` always ANDs tenant + data scope; a filter can only narrow; an out-of-scope id returns empty, not 403 |
| Cross-tenant read | any member | tenant predicate always added, even for `SystemActor` |
| Code path forgetting scope | developer | no `Compile` without an `Actor`; `SystemActor` call sites lint-allowlisted |
| Count oracle on a field the caller may not see | restricted member | field `Permission`: filtering, sorting or grouping by it without the permission is `INVALID_FILTER` ("unknown field", no existence leak) |
| DoS through deep nesting, huge lists, huge bodies, costly operators | any caller | limits in §3.7; `contains` only on indexed fields; statement timeout; deep-offset cap |
| Stored filter replay after the registry changed | system | stored documents are re-validated on every run; never store SQL |
| Free text in logs | operator | gateway redacts `q`, `search`, `*_contains`, `file_path`, `email`; the API logs param names only; `/search` bodies never logged; error bodies never echo free text |
| Unknown-param metrics as an unbounded label set | any caller | the param label is the registry name, or `other` for names outside `[a-z0-9_]{1,64}` |

## 5. Authorization and tenant isolation

- `POST /{resource}/search` and `/export` need the **same permission as the
  list** (`findings:read` for findings) and the same module gate.
- Every compiled query is `tenant_id = $tenant AND <scope> AND <filter>`.
  `<scope>` is the `user_accessible_assets` predicate for a restricted actor
  (the same SQL as `postgres.dataScopeCond`; a test pins them together).
- A field may carry a permission (for example pentest-only fields); without
  it the field does not exist for that actor.
- Export is audit-logged with the canonical filter (no free-text values) and
  the row count.

## 6. Tests required

- Parser fuzzing (`FuzzParseValues`, `FuzzParseDocument`): no panic; either an
  error or a spec within limits; the compiled SQL has as many placeholders as
  arguments.
- Injection suite: SQL metacharacters in every position (field, op, value,
  sort, `q`) never reach the SQL text.
- Cross-scope matrix (integration DB): for an admin and a restricted member,
  list total == stats total == Σ groups == export rows for a table of filters;
  filters targeting out-of-scope data return zero everywhere.
- Field-permission test, saved-view IDOR test (when views ship).

## 7. Alternatives rejected

- `?filters={json}` (D1 b): see §1.
- An expression string (AIP-160, OData `$filter`, RSQL) now (D7 c): a grammar
  is attack surface and gives no typed clients. It can be added later as a
  third encoding of the same AST, with SQL precedence.
- Bracket operators (`field[gte]=`): percent-encoding noise and OpenAPI
  `deepObject` gaps.
- Value-prefix operators (`field=gte:x`): breaks values containing colons.

## 8. Plan

| Phase | PR | Content |
|---|---|---|
| P0 | this RFC | RFC, index, architecture page |
| P0 | `pkg/filterspec` | registry, both parsers, AST, `Compile` with mandatory actor, limits, `INVALID_FILTER`, unknown-param warn/strict, fuzz and injection tests. No endpoint uses it yet |
| P1 | findings list | `GET /findings` on the parser; old names as aliases with deprecation headers and a metric; `asset_tags` read |
| P1 | findings stats and groups | same `Spec`; one WHERE builder; cross-scope contract test (list = stats = groups = export) |
| P1 | research 17 filters | CVSS range, first/last seen, port/protocol, plugin family, assignee, asset criticality, exploit available, asset tag; indexes where needed |
| P1 | `POST /findings/search` | document parser on the wire; `GET /meta/filters/findings` |
| P1 | OpenAPI | params generated from the registry; `openapicontract` check E |
| P2 | export | `POST /findings/export`: scoped, audit-logged, formula-injection-safe CSV, streamed by keyset, rate-limited |
| P2 | web | URL codec with the API params; old links aliased once |
| P2 | saved views | `saved_views` with a `FilterDocument`, validated on save and run |
| P3 | assets, MCP | same steps |
| P4+ | long tail | one resource per PR |
| P5 | removal | aliases removed per RFC-041 D10 |

## 9. Owner decisions (2026-10-04)

| # | Decision | Chosen |
|---|---|---|
| D1 | Shape | **flat GET + `POST /{resource}/search` FilterDocument, one AST**; `?filters={json}` rejected |
| D2 | Field names | singular = response field name; plurals as aliases |
| D3 | Arrays | comma canonical, repeated keys tolerated |
| D4 | Operators | suffixes `_gte`, `_gt`, `_lte`, `_lt`, `_not`, `_null`, `_contains` |
| D5 | Full text | `q` (alias `search`) |
| D6 | Strictness | unknown or invalid params: log, count and `Deprecation` header for one release, then 400 `INVALID_FILTER`; bad values for known params 400 at once |
| D7 | Expression string | later, as an optional third encoding, SQL precedence |
| D8 | Search spelling | `POST /{coll}/search` |
| D9 | Pagination and counts | offset ≤ 10,000 then cursor; exact count until a threshold, then estimate |
| D10 | Log privacy | redact free-text params at the gateway; API logs param names only |
| D11 | Order | findings → stats/groups/export → saved views → assets → MCP → long tail |
| D12 | Stored-filter actor | views as the viewer; reports, alerts, campaign progress as their owner; system use only via an allowlisted `SystemActor` |
