# Custom query language

Users write short text queries over their own data, for example

```
findings where state = open and severity = critical and is_in_kev = true
  and asset.internet_facing = true and first_detected_at < -14d | count
```

and get a number, a grouped table or a time series back. The same query will
later back dashboard widgets, saved queries and alerts. Design and decisions:
[RFC-115](../rfcs/RFC-115-custom-query-language.md).

**Shipped:** the language (parser, canonical printer, query document v2), the
findings and assets entities, the aggregation pipeline, the plan layer with
every server-side rule, the PostgreSQL executor and three endpoints
(`POST /api/v1/query/explain`, `POST /api/v1/query/run`,
`GET /api/v1/query/schema`).
**Planned:** more entities (EASM changes, scans, sensors, remediation, audit),
saved and versioned queries with sharing and audit, the fact-table fast path
and cost estimator, query-bound dashboard widgets, the web editor, row lists
(`fields`), export, alerts.

## Grammar

```
query    := [entity] ["where" expr] ("|" stage)*      -- entity defaults to findings
entity   := findings | assets
expr     := expr "or" expr | expr "and" expr | "not" expr | "(" expr ")" | term
term     := path ("=" | "!=" | ">" | ">=" | "<" | "<=" | "~") value
          | path ["not"] "in" "(" value ("," value)* ")"
          | path "between" value "and" value
          | path "is" ["not"] "empty"
          | "text" "~" string                         -- the entity's text search
path     := field | relation "." field                -- curated relations only
value    := string | number | true | false | word | relative | me
string   := '"' ... '"'                               -- escapes: \" and \\
relative := "-" digits ("h" | "d" | "w" | "mo" | "y") -- -14d = 14 days ago; mo = 30 d, y = 365 d
stage    := "count" ["by" path ("," path)*]
          | "stats" agg ("," agg)* ["by" path ("," path)*]
          | "bucket" timefield "by" ("day" | "week" | "month")
          | "top" N "by" column                       -- N <= 100, descending
          | "sort" column ["asc" | "desc"] ("," ...)* -- <= 3 keys
          | "limit" N                                 -- N <= 1000
agg      := count() | distinct(dimension) | sum|avg|min|max|median|p90(measure) ["as" name]
```

- Keywords and field names are case-insensitive; values keep their case. `and`
  binds tighter than `or`; `not` tighter than both. Words that are keywords
  (`and`, `in`, `by`, ...) must be quoted when used as values.
- Dates are quoted: `"2026-01-31"` or RFC 3339. Relative times are bare.
- Pipeline order: an optional `bucket`, then at most one `count` or `stats`
  (a plain `count` when there is none), then `top` or `sort`, and `limit`.
  `top`, `sort` and `limit` need a grouped result (row lists come with the
  `fields` stage later).
- Output columns are the bucket field, the group paths, then the aggregates
  (`count`, `avg_cvss_score`, or the `as` name). `sort` and `top` name them.
- `Format` prints the canonical text (lower-case keywords, minimal
  parentheses). `Parse(Format(q))` gives the same tree, and a version 1 filter
  document (a saved view) converts to text and back to the same document
  (`FromSpec`).

### Query document v2

```json
{"v":2, "entity":"findings",
 "filter":{"all":[{"field":"severity","op":"in","value":["critical","high"]}]},
 "q":"log4j",
 "pipeline":[{"count":{"by":["asset.type"]}}, {"top":{"n":5,"by":"count"}}]}
```

`filter` and `q` are exactly the version 1 FilterDocument
([list query contract](list-query-contract.md)), with relative times resolved.
The server-side filters below are never stored in it: they are added at every
run.

## Entities and fields

Every field comes from the entity's `filterspec` registry, the same allowlist
the list endpoints use. Nothing builds SQL from a name the registry does not
hold. `GET /api/v1/query/schema?entity=` lists what the caller may use (types,
operators, enum values, and which paths can be grouped, aggregated or
bucketed).

| Entity | Permission | Registry | Group by | Aggregate | Bucket |
|---|---|---|---|---|---|
| `findings` | `findings:read` | `vulnerability.FindingFields` + relation fields | severity, status, source, sla_status, priority_class, finding_type, observation, validation, tool_name, family, cve_id, rule_id, is_in_kev, is_reachable, network_transport, network_service, asset.type, asset.criticality, asset.environment, asset.exposure, asset.internet_facing, asset.crown_jewel | cvss_score, epss_score | first_detected_at, last_seen_at, resolved_at, created_at |
| `assets` | `assets:read` | `asset.AssetFields` | type, sub_type, criticality, status, scope, exposure, environment, data_classification, internet_facing, crown_jewel, discovery_source, provider | risk_score | first_seen, last_seen, discovered_at, created_at |

**Curated relation (findings → asset):** `asset.type`, `asset.criticality`,
`asset.environment`, `asset.exposure`, `asset.internet_facing`,
`asset.crown_jewel`, `asset.tag`, `asset.owner_id`. They need `assets:read` as
well; without it they are unknown fields. Each reads the asset with its own
tenant predicate. No free joins, no sub-queries.

Not in any registry: tenant ids, secrets, tokens, password hashes, credential
material, free-form properties and personal contact data.

## Security model

| Rule | Where it lives | A query can |
|---|---|---|
| Tenant predicate (first conjunct) | filterspec actor, built from the authenticated principal | never name or change it |
| Data scope (`user_accessible_assets`) and hidden program assets | filterspec actor (`ScopeSQL`) | never widen it |
| Pentest member rule (`FindingMemberVisibilitySQL`: campaign members only, no draft or in-review for the client role) | the findings registry's `MemberVisibility`, for every non-administrator | never bypass it |
| Draft and in-review pentest findings left out | entity mandatory filter | `status = draft` returns 0 |
| Branch-only findings left out | entity mandatory filter | `branch_only = true` returns 0 |
| Findings on, and assets that are, bug-bounty program assets left out | entity mandatory filter (internal field) | not name the field |
| Deleted assets left out | entity mandatory filter (internal field) | not name the field |
| Entity permission | plan layer | an entity without it is refused |
| Field permission | plan layer (and the compiler again) | a forbidden field is "unknown field", exactly like a missing one |

- **Compilation only.** Text → AST → filterspec document → registry-checked
  AST → SQL with numbered parameters. Values are always bound; field SQL is a
  registry constant; the pipeline's SQL is constants in `pgsql`. A fuzz test
  checks that replacing every string literal does not change the SQL text.
- **Principal from the server.** The handler takes only `{"query": "..."}`
  (unknown body fields are rejected); tenant, user, admin flag, permissions and
  data scope come from the authenticated context and
  `datascope.Enforcer.ResolveFor`. A member's query with no enforcer, or a
  failed scope lookup, is an error (fail closed). A user-less API key resolves
  to a scope with no rows.
- **Errors** carry byte ranges, lines and columns, and never echo string
  literals.

### Threat model

| Threat | Control |
|---|---|
| SQL injection | grammar has no SQL; registry constants; bound parameters; fuzzed parser and compiler; injection tests |
| Cross-tenant read | tenant predicate first in every statement from the principal; relation reads pin the tenant; DB tests with two tenants |
| Reading outside one's data scope, pentest campaigns, drafts, program assets | injected by the plan layer, not by the text; DB tests per rule |
| Field discovery | forbidden and unknown fields answer the same; the schema hides forbidden fields |
| Denial of service | input limits, complexity score, group and row caps, read-only transaction, 5 s statement timeout, `work_mem` cap, per-user rate limit, per-user (2) and per-tenant (4) concurrency |
| Differencing via text search | moot inside one's own scope (the caller can list the same rows) |
| Learning other tenants' volumes from planner estimates | Explain returns only a coarse cost class, never row estimates |

## Limits

| Limit | Value |
|---|---|
| Query text | 4096 bytes, 512 tokens, nesting 16 |
| Filter | filterspec limits: 50 conditions, depth 3, 100 values per list (500 in documents), 200 characters per value |
| Pipeline | 6 stages, 2 groups (a bucket counts), 5 aggregates, 3 sort keys, top <= 100 |
| Result | 1000 rows (`truncated` is set when more existed) |
| Complexity score | <= 100: 1 + conditions + 2 per relation condition + 3 per text search + 2 per group (+3 for a relation group) + 2 for a bucket + 1 per aggregate (+2 for distinct, median, p90) + stages |
| Execution | READ ONLY transaction, `statement_timeout` 5 s (422 on timeout), `work_mem` 32 MB |
| Rate | per user: burst 30, 1 request/s on explain and run; 2 concurrent per user, 4 per tenant and 8 in total per API process, so queries hold at most a third of the default connection pool (429) |

## Execution backends

The compiled query is a backend-neutral `querylang.Plan`: the entity, the
filterspec AST (caller's filter plus mandatory filters), the pipeline (bucket,
groups, aggregates, order, limit) and the security context (the filterspec
actor with tenant, data scope and member rule; the field permission checks are
already applied). An `Executor` has two calls:

```go
type Executor interface {
    Explain(ctx context.Context, p *Plan) (Estimate, error)
    Run(ctx context.Context, p *Plan) (*Result, error)
}
```

The only implementation is PostgreSQL (`postgres.QueryExecutor`, SQL from
`pgsql.Render`) over the raw tables; the per-asset fact tables will be a
faster path inside the same executor. Another backend (for example a columnar
store) would implement the same interface over the same plan and inherit every
injected rule, without changing the language, the API or the security model.

## API

| Route | Gate | Body / params | Result |
|---|---|---|---|
| `POST /api/v1/query/explain` | `findings:read` or `assets:read`, then the entity's and fields' own | `{"query": "..."}` | canonical text, description, columns, scope (kind and the rules applied), score, limit, cost class (`low`, `medium`, `high` from the planner's estimate; raw planner numbers are not returned because table statistics span tenants), document v2 |
| `POST /api/v1/query/run` | same | `{"query": "..."}` | columns, rows, truncated, elapsed_ms, scope |
| `GET /api/v1/query/schema?entity=` | same | entity | fields the caller may use |

Interactive runs are not stored, so they are not audited; saved queries (and
their versions, sharing and deletion) will be.

## Key files

- `api/pkg/querylang/` — lexer, parser, printer, entities, plan, pipeline, description, document v2
- `api/pkg/querylang/pgsql/` — SQL rendering, golden files under `testdata/golden`
- `api/pkg/domain/asset/asset_fields.go` — the assets registry
- `api/pkg/filterspec/registry.go` — `Registry.Extend`
- `api/internal/infra/postgres/query_executor.go` — read-only execution, timeout, estimate
- `api/internal/app/query/` — principal resolution, concurrency, service
- `api/internal/infra/http/handler/query_handler.go`, `routes/query.go`

## Matching findings (tasks from a query)

`query.Service.MatchFindings` runs a filter-only findings query (`findings where ...`, no pipeline) as a
caller and returns the matching ids instead of rows: the count and the first N ids, oldest first, from
`pgsql.RenderMatch` (the same compiled WHERE clause as `Render`, narrowed by `MatchOptions`: excluded statuses
and sources, and "not the primary member of a remediation task"). It shares the principal resolution, rules,
limits and concurrency caps of `Run`. A background caller (an auto-mode remediation task) passes its stored
owner with their current role and permissions; `Caller.Owner` carries the owner flag that a request would
otherwise provide. Used by remediation tasks (RFC-098 §13).

`POST /api/v1/query/from-filters` turns a findings list query string into query text through the list's own
filter registry (`querylang.FromSpec`); params that are not filters are returned as `ignored`.
