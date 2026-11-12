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
short form for search boxes (below), the findings, assets and scans entities, the
aggregation pipeline, the plan layer with every server-side rule, the
PostgreSQL executor and five endpoints (`POST /api/v1/query/explain`,
`POST /api/v1/query/run`, `GET /api/v1/query/schema`,
`POST /api/v1/query/parse`, `GET /api/v1/query/values`), and the shared
`QueryInput` search box in the web.
**Planned:** more entities (EASM changes, scans, sensors, remediation, audit),
saved and versioned queries with sharing and audit, the fact-table fast path
and cost estimator, query-bound dashboard widgets, the web editor, row lists
(`fields`), export, alerts.

## Grammar

```
query    := [entity] ["where" expr] ("|" stage)*      -- entity defaults to findings
entity   := findings | assets | scans
expr     := expr "or" expr | expr "and" expr | "not" expr | "(" expr ")" | term
term     := path ("=" | "!=" | ">" | ">=" | "<" | "<=" | "~") value
          | path ["not"] "in" "(" value ("," value)* ")"
          | path "between" value "and" value
          | path "is" ["not"] "empty"
          | "text" "~" string                         -- the entity's text search
path     := field | relation "." field                -- curated relations only
value    := string | number | true | false | word | relative | me
string   := '"' ... '"'                               -- escapes: \" and \\
relative := "-" digits ("m" | "h" | "d" | "w" | "mo" | "y") -- -14d = 14 days ago; mo = 30 d, y = 365 d
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

## Short form (search boxes)

The filter part of the language has a second spelling for search boxes, where
the page already says which entity is searched:

```
severity>=high kev=true -status:accepted last_seen<7d domain=*.example.com log4j
```

It parses to the same AST as the long form (`querylang.ParseFilter`), so it
builds the same filter document through the same plan and every server-side
rule applies unchanged. Text that starts with an entity name or `where` is
read as the long form; both are accepted in the same box.

```
search := clause (sep clause)*            -- max 50 conditions, nesting 16
sep    := space | " AND " | " OR "        -- a space is AND; AND binds tighter than OR
clause := ["-" | "NOT "] atom
atom   := path op value
        | path (":" | "=") value ("," value)*     -- any of
        | path (":" | "=") lo ".." hi             -- range, either end may be empty
        | path " is " ["not "] "empty"
        | "(" search ")"
        | word | '"' phrase '"'                   -- text search
op     := "=" | "!=" | ">" | ">=" | "<" | "<=" | "~"
```

| Short form | Meaning | Document |
|---|---|---|
| `severity=critical`, `severity:critical` | equal | `in` |
| `severity:critical,high` | any of | `in` |
| `-status:accepted`, `status!=accepted` | not | `not_in` (`ne`, or `eq` with the opposite value on a boolean) |
| `severity>=high` | ordered values: at least high | `in ["critical","high"]` (fields marked `Ordered`: severity, priority class, asset criticality) |
| `file_path~"src/main"` | contains, case-insensitive, at least 3 characters | `contains` |
| `asset.name=api-*`, `domain=*.example.com` | name patterns (`*`, `?`) on fields marked `Glob` | the field's pattern or membership keys |
| `ip=10.0.0.0/8`, `ip:10.0.0.0/8,192.168.0.0/16` | the asset's address is inside a range | `asset_ip in [...]` (`idx_assets_ip_addr`) |
| `port:8000..8999`, `cvss:7..` | range | `gte` + `lte` |
| `last_seen<7d` | age: seen less than 7 days ago | `last_seen_at gt "-P7D"` |
| `last_seen<-7d` | a point in time: before 7 days ago | `last_seen_at lt "-P7D"` |
| `assignee is empty` | no value | `is_null` |
| `log4j`, `"sql injection"` | text search | `q` |
| `10.0.0.0/24`, `CVE-2024-3400` (bare) | typed: the asset address, the CVE | `asset_ip`, `cve_id` |

- `=` is exact; `*` and `?` are patterns only on name fields, and on other
  fields an unquoted `*` is a `pattern_not_allowed` problem (quote it to match
  it literally); `~` is contains. There are no regular expressions.
- Unsigned durations (`7d`, `12h`, `30m`, `2w`, `3mo`, `1y`) are ages and need
  `<`, `<=`, `>` or `>=`; signed ones (`-7d`) are points in time as in the long
  form. The document keeps the relative value (`-P7D`), so a saved filter
  stays relative.
- Short names resolve to fields: `cve`, `kev`, `epss`, `cvss`, `tool`, `rule`,
  `priority`, `sla`, `assignee`, `port`, `service`, `transport`, `last_seen`,
  `age` (first detected), and the asset attributes `domain`, `ip`,
  `criticality`, `environment`, `exposure`, `internet_facing`, `crown_jewel`.
  Names that would be ambiguous (`name`, `type`, `status`, `tag`) need the
  `asset.` prefix for the asset. The printer always prints the canonical path.
- Plain words of one AND group are one text search, as the box always read
  them (`log4j severity=high apache` searches "log4j apache"). A bare address
  or CVE id becomes a condition only when the caller may use that field;
  otherwise it stays text. A field name the caller may not use is an
  `unknown_field` problem, never a text search, so a typo cannot widen a bulk
  action.
- `FormatShort` prints the canonical short text (paths, `=` for one value and
  `:` for a list, ages, `>=` runs of ordered values, `-(...)` for negated
  groups, `OR` in capitals). `ParseFilter(FormatShort(FromDocument(doc)))`
  builds the same document; `FuzzParseShort` checks it on random input.

### Problems

Every problem has a `code`, an English `message`, its byte range and line and
column, and `suggestions` where a fix exists: `syntax`, `unknown_field` ("did
you mean" over the paths and short names the caller may use, within two
edits), `operator_not_allowed` (the allowed operators), `unknown_value` (the
closest enum values), `bad_value`, `pattern_not_allowed`, `wrong_entity`,
`pipeline_not_allowed`, `too_complex`, and from `POST /query/parse`
`not_on_list`. Messages never repeat a value from the query; the web shows the
person's own text from its own state, and translates the code.

### Search box endpoints

| Route | Gate | Input | Result |
|---|---|---|---|
| `POST /api/v1/query/parse` | `findings:read`, `assets:read` or `scans:read`, then the entity's own; burst 30, 5/s per user | `{"entity", "text"}` or `{"entity", "document"}` or `{"entity", "params"}` (a list URL's query string) | `valid`, `form`, canonical short `text`, long `query`, the version 1 `document` (relative times kept), `chips` (top-level conditions, or one `advanced` chip that is never flattened), the list's flat `params` when every chip has one, `problems`. Reads no data; a problem is 200 with `valid: false` |
| `GET /api/v1/query/values?entity=&field=&prefix=&fq=` | same; burst 20, 2/s per user | a groupable field (a path or short name), a prefix, the box's filter | up to 20 values with counts, under the filter minus the field's own conditions; `counted: false` when the 1 s budget ran out (enum and boolean values are then listed without counts). Cached 60 s per tenant, user and request |

Values run as `<entity> where <filter> | count by <field> | sort count desc |
limit N` through `Build` and the executor, so the tenant, the data scope, the
pentest member rule and the mandatory exclusions apply exactly as for the
list; there are no precomputed counts that could leak across scopes. A
document from `parse` is also checked against the findings list registry, so
the box never hands `POST /findings/search` a filter it refuses.

### Web

`QueryInput` (`web/src/features/query/components/query-input.tsx`) is the one
search box component: completion of fields (from `GET /query/schema`),
operators and values (enum and boolean values and ages locally, others from
`GET /query/values`), the first problem with its fixes as buttons, a status
line with the result count (exact up to 10,000, then "10,000+"), recent
queries per entity in `localStorage` (cleared at sign-out, at session end and
on organization switch), and the keyboard: Tab or Enter accepts a
suggestion, Enter runs, Ctrl+Space opens suggestions, Up in an empty box
recalls the last query, Esc closes then leaves. The remediation hub's
"task from a query" dialog uses it (tasks store the long form the server
printed).

## Entities and fields

Every field comes from the entity's `filterspec` registry, the same allowlist
the list endpoints use. Nothing builds SQL from a name the registry does not
hold. `GET /api/v1/query/schema?entity=` lists what the caller may use (types,
operators, enum values, and which paths can be grouped, aggregated or
bucketed).

| Entity | Permission | Registry | Group by | Aggregate | Bucket |
|---|---|---|---|---|---|
| `findings` | `findings:read` | `vulnerability.FindingFields` + relation fields | severity, status, source, sla_status, priority_class, finding_type, practice, compliance_result, observation, validation, tool_name, family, cve_id, rule_id, is_in_kev, is_reachable, network_transport, network_service, asset.type, asset.criticality, asset.environment, asset.exposure, asset.internet_facing, asset.crown_jewel | cvss_score, epss_score | first_detected_at, last_seen_at, resolved_at, created_at |
| `assets` | `assets:read` | `assetlist.Fields` (every filter of `GET /assets`, list-query-contract.md) | type, sub_type, criticality, status, scope, exposure, environment, data_classification, internet_facing, crown_jewel, discovery_source, provider | risk_score | first_seen, last_seen, discovered_at, created_at |
| `scans` | `scans:read` | `scan.Fields` | status, scan_type, schedule_type, sensor_preference, origin, last_run_status | total_runs, failed_runs | created_at, last_run_at, next_run_at |

**Scans.** A scan is tenant configuration (schedule, targets, tool), not an
asset row, so the data scope does not narrow the entity (its registry is
`Unscoped`, with the reason recorded): every caller with `scans:read` sees the
tenant's saved scans, as `GET /scans` always listed them. Two server rules
apply to every query, as mandatory internal filters the language cannot name
or cancel: archived scans are left out, and so are quick scans that were never
saved. The scans the platform manages (`origin=system`) are listed by
`GET /scans?origin=system`, not by a query. `scan_type`, `schedule_type`,
`status` and `origin` match the list endpoint's parameters exactly, and a
document `parse` returns is checked against the list registry like findings.

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
| `POST /api/v1/query/explain` | `findings:read`, `assets:read` or `scans:read`, then the entity's and fields' own | `{"query": "..."}` | canonical text, description, columns, scope (kind and the rules applied), score, limit, cost class (`low`, `medium`, `high` from the planner's estimate; raw planner numbers are not returned because table statistics span tenants), document v2 |
| `POST /api/v1/query/run` | same | `{"query": "..."}` | columns, rows, truncated, elapsed_ms, scope |
| `GET /api/v1/query/schema?entity=` | same | entity | fields the caller may use |
| `POST /api/v1/query/parse` | same | `{"entity", "text" \| "document" \| "params"}` | search box check ("Short form", above) |
| `GET /api/v1/query/values` | same | `entity`, `field`, `prefix`, `fq` | value completion with counts ("Short form", above) |

Interactive runs are not stored, so they are not audited; saved queries (and
their versions, sharing and deletion) will be.

## Key files

- `server/pkg/querylang/` — lexer, parser, printer, entities, plan, pipeline, description, document v2;
  `short.go` (short form parser), `printer_short.go` (`FormatShort`, `FromDocument`), `suggest.go` ("did you mean")
- `server/internal/app/query/parse.go`, `values.go` — search box check and value completion
- `web/src/features/query/` — `QueryInput`, completion, recent queries
- `server/pkg/querylang/pgsql/` — SQL rendering, golden files under `testdata/golden`
- `server/pkg/domain/asset/asset_fields.go` — the asset column fields
- `server/pkg/domain/assetlist/fields.go` — the asset inventory registry (columns, relations, derived states) the assets entity uses
- `server/pkg/filterspec/registry.go` — `Registry.Extend`
- `server/internal/infra/postgres/query_executor.go` — read-only execution, timeout, estimate
- `server/internal/app/query/` — principal resolution, concurrency, service
- `server/internal/infra/http/handler/query_handler.go`, `routes/query.go`

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
