# List query contract

How list, stats, groups, search and export endpoints read their filters. The
design, its evidence and the decisions are in
[RFC-048](../rfcs/RFC-048-list-query-contract.md).

## The rule

Every migrated collection endpoint parses its filter through
`pkg/filterspec` against the resource's field registry and compiles it with
`filterspec.Compile`. Nothing else builds a WHERE clause from request input.

```
GET  /api/v1/findings?severity=critical,high&epss_score_gte=0.1&q=log4j&sort=-priority_class
POST /api/v1/findings/search   {"v":1,"filter":{"all":[…]},"sort":["-epss_score"]}
```

Both decode into the same `filterspec.Spec`. `Compile` always prepends the
tenant predicate and, for a restricted caller, the data-scope predicate.

## Adding a filterable field

1. Add a `filterspec.Field` to the resource registry with:
   - `Name`: singular snake_case, equal to the response field, not ending in
     an operator suffix;
   - `Type` and `Ops`: only the operators the field supports;
   - `SQL`: a constant column or expression. Never build it from input;
   - `Indexed`: true only when an index backs range or `in` filters;
   - `Permission` when the field is not visible to every reader.
2. If the field is computed from another table, its SQL is a template whose
   subquery carries the tenant itself (`a.tenant_id = {tenant}`); `{user}`
   binds the acting user. A boolean predicate that a partial index can serve
   is a `BoolTemplate`.
3. Add an index in the same PR if the table is large, with an `EXPLAIN` in the
   PR description (one `CREATE INDEX CONCURRENTLY` per migration file).
4. Run `go run ./tools/gen/filterparams` and `make swagger` from `api/`: the
   `@Param` lines between `// filterspec-params:` markers are generated from
   the registry, and `TestOpenAPIDocumentsFilterParams` fails when the spec
   and the parser disagree.
5. The registry test fails on suffix-ending names, missing enums or ops the
   type cannot support.

## Findings (the first migrated resource)

| Endpoint | Notes |
|---|---|
| `GET /findings` | `vulnerability.FindingFields`; old names (`severities`, `search`, ...) are aliases |
| `GET /findings/stats`, `GET /findings/groups` | the same params and the same compiled WHERE, so their counts match the list |
| `POST /findings/search` | the FilterDocument form: OR, nesting, up to 500 ids |
| `GET /meta/filters/findings` | the machine-readable contract and the document JSON Schema |

The registry also carries the findings visibility rule every non-admin
caller gets: pentest findings only for members of their campaign.

## Actors

| Constructor | When | Effect |
|---|---|---|
| `filterspec.UserActor(UserActorInput{...})` | any request; `Scope` comes from `datascope.Enforcer.Resolve` | tenant + data scope (nil scope = unrestricted caller) + the registry's member visibility rule for non-admins |
| `filterspec.SystemActor(tenantID, reason)` | background jobs that produce admin-only output | tenant only; call sites are allowlisted |

There is no constructor without a tenant.

## Errors

A bad filter is `400` with code `INVALID_FILTER` and `details[]` naming the
`param` (GET) or JSON `path` (POST). Free-text values are never echoed.

## Unknown params and aliases

- During an endpoint's first release on the contract, unknown params are
  ignored but logged by name, counted in `filter_unknown_param_total`, and
  answered with `Deprecation` and `Warning` headers. Then the endpoint
  switches to strict (400).
- Old names (`severities`, `search`, …) are aliases: they work, answer with
  `Deprecation`/`Sunset` and count in `deprecated_query_param_requests_total`.

## Limits

50 leaves, depth 3, 100 values per list (500 for id fields in POST), 200
characters per value (`q` 255), 32 KB POST body.

## Export

`GET|POST /findings/export` streams CSV or NDJSON in keyset batches of 1,000
(60 s statement timeout per batch), at most 100,000 rows, needs
`findings:export`, and is audit-logged as `data.exported` with the filter's
field:operator shape (never its values). CSV cells a spreadsheet would run as
formulas are neutralized.

**Known limit (follow-up):** "one export per user at a time" is an in-process
slot, so it holds per API instance. The platform runs one API replica today
(RFC-046); before running several, move the slot to a shared limiter (Redis
key with a TTL, or a row lock). The per-user rate limit already applies across
instances.

## Saved views

Saved views (UI contract D15) live in `saved_views` (migration 000777) and
`/api/v1/views`:

- A view stores a FilterDocument (from a document or from the page's flat
  query) plus page state (`group_by`, `columns`, `density`). Never SQL, never
  results. The filter is validated on save and again every time the view
  runs; a stored filter the registry no longer accepts is `400
  INVALID_FILTER`.
- A view is personal, or shared with one active group the owner belongs to.
  Members of the group use it; only the view's owner edits or deletes it
  (decision A1); others duplicate it. 100 views per person, 100 per group.
- A view runs as the person using it (decision A5): `?view=<id>` on
  `/findings`, `/findings/stats`, `/findings/groups` and `/findings/export`
  compiles the view's filter as the caller, with the request's own params
  overriding it field by field (`filterspec.Overlay`). Sharing a view shares
  a query, not anyone's rows.
- Every read and write is tenant-bound; a view the caller may not see (or of
  another tenant) is 404. Changes are audit-logged (`saved_view.*`).
