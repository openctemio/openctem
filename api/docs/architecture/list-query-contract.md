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
| `GET /findings/quick-views` | the built-in quick views with the caller's counts (below) |

The registry also carries the findings visibility rule every non-admin
caller gets: pentest findings only for members of their campaign.

### Quick views

`GET /findings/quick-views` (`findings:read`, heavy-read limiter) returns the
list's built-in views in display order, each with the caller's count and the
`GET /findings` query string that lists it:

| Key | `params` |
|---|---|
| `active` | `state=open` (+ `&informational=false`, see below) |
| `needs_triage` | `status=new&informational=false` |
| `my_queue` | `state=open&related_to=me` (+ `&informational=false`) |
| `sla_breached` | `state=open&sla_status=overdue,exceeded` (the stats `sla_breached` rule; + `&informational=false`) |
| `pending_approval` | `pending_approval=true` |
| `accepted_expiring` | `status=accepted&acceptance_expires_at_lte=P30D` |
| `closed` | `state=closed` (fixed and dispositioned) |

The work views (`active`, `my_queue`, `sla_breached`) leave informational
findings out unless the caller's preference, else the organization's default,
includes them; `needs_triage` always leaves them out, the response's
`include_informational` says which applied, and such a view carries
`informational_hidden` (how many it leaves out)
([findings-work-views.md](findings-work-views.md)).

The definitions live in one place (`vulnerability.FindingQuickViews`). Each
view's params are parsed with the strict registry and compiled with
`filterspec.CompileFacets`: the base WHERE is the caller's scoped one (tenant,
data scope, pentest membership, the list's default branch rule) and each view
is a `COUNT(*) FILTER (WHERE ...)` over it, in one read-only statement with the
5 s list timeout (503 when it runs out). A count therefore always equals the
total of `GET /findings?<params>` for the same caller. There is no server
cache, so a scope change applies on the next read; the response may be cached
privately for 60 s.

Fields added for the views: `pending_approval` (an approval request for the
finding is pending), `acceptance_expires_at` (ranges; unset unless accepted)
and the `closed` value of `state`.

## Actors

| Constructor | When | Effect |
|---|---|---|
| `filterspec.UserActor(UserActorInput{...})` | any request; `Scope` comes from `datascope.Enforcer.Resolve` | tenant + data scope (nil scope = unrestricted caller) + the registry's member visibility rule for non-admins |
| `filterspec.SystemActor(tenantID, reason)` | background jobs that produce admin-only output | tenant only; call sites are allowlisted |

There is no constructor without a tenant.

## Certificates (`GET /attack-surface/certificates`)

The Certificates view of the external attack surface reads certificate assets
through the `certificates` registry (`pkg/domain/certificate`), with no new
storage: every column is a property of the asset (`subject_cn`, `issuer_cn`,
`issuer_org`, `not_before`, `not_after`, `fingerprint_sha256`). The data scope
applies to the certificate asset itself, so a certificate is listed exactly
when its asset is visible; soft-deleted assets and other asset types are never
listed. `status` (`expired`, `expiring_soon`, `ok`, `unknown`) is computed at
read time from `not_after` (`expiring_soon` is under 30 days left; a missing or
unparsable date is `unknown`, never `ok`), is filterable and sortable, and is
returned on every row with `days_to_expiry`. `GET /attack-surface/certificates/stats`
counts the same filtered set by status. Both need `assets:read`. Subjects and
issuers are chosen by whoever issued the certificate: clients render them as
text.

## Technologies (`GET /attack-surface/technologies`)

The Technologies view reads `asset_technologies` through the `technologies`
registry (`pkg/domain/technology`) in two stages. The row stage is one row per
asset and technology, joined to the software version the detection was
matched to; the tenant predicate, the data scope (on each row's asset) and
every filter apply there. The group stage folds the rows into one row per
technology and version and adds the CVE figures and the open alert count.
Filter fields are therefore row-stage columns and sort keys group-stage
columns: `asset_count`, `cve_count`, `top_cvss` and `active_alerts` are sort
keys only (filtering on them is `400`). A version is listed exactly when one
visible asset runs it, and every count covers visible assets only. `GET
/attack-surface/technologies/stats` counts the same filtered versions (all,
with CVEs, with a known-exploited CVE, of unknown version, with open alerts).
Both need `assets:read`. Names, versions and vendors are scan output: clients
render them as text.

## Errors

A bad filter is `400` with code `INVALID_FILTER` and `details[]` naming the
`param` (GET) or JSON `path` (POST). Free-text values are never echoed.

## Unknown params and aliases

- Every list endpoint on the contract is strict: an unknown param is `400
  INVALID_FILTER` with `details[].param` naming it and `details[].reason`
  `"unknown filter"` (the value is never echoed). A typo can never widen a
  list, its counts, an export or a bulk change. The findings list, stats,
  groups and export switched to strict when the findings list page moved to
  the registry-driven filter bar (research 234); `GET /meta/filters/findings`
  lists the accepted names.
- Old names (`severities`, `search`, …) are aliases: they work, answer with
  `Deprecation`/`Sunset` and count in `deprecated_query_param_requests_total`.

## Findings search (`q`)

`q` on the findings list, stats, groups and export matches, inside the
caller's compiled scope:

| Field | Match | Index |
|---|---|---|
| title | contains, case-insensitive | `idx_findings_title_trgm` (GIN `gin_trgm_ops`) |
| file path | contains | `idx_findings_file_path_trgm` |
| rule id | contains | `idx_findings_rule_id_trgm` |
| CVE id | exact, case-insensitive (`cve_id` or any of `cve_ids`) | `idx_findings_tenant_cve`, `idx_findings_cve_ids` |
| asset name | contains (assets of the caller's tenant) | `idx_assets_name_trgm` |

The description is not part of `q`: it is the opt-in `description` filter
(`description_contains=…`). `GET /meta/filters/findings` lists the searched
fields in `contract.search_fields` (`title, file_path, rule_id, cve_id,
asset_name`), so a search box can say what it searches. `q` is bound as a
parameter (LIKE metacharacters escaped) and is at most 255 characters.

Every arm of the search can use an index, so the planner can combine them
instead of reading all the tenant's findings. The list, count, stats and SLA
breakdown each run in a read-only transaction with a 5 s statement timeout; a
read that runs out of time is `503 QUERY_TIMEOUT` ("narrow the search or the
filters"). `GET /findings`, its stats and groups are under the heavy-read rate
limiter.

## Limits

50 leaves, depth 3, 100 values per list (500 for id fields in POST), 200
characters per value (`q` 255), 32 KB POST body.

## Export

`GET|POST /findings/export` streams CSV or NDJSON (`format=ndjson`):

- **Scope and filter**: the list's filter, parsed strictly (an unknown param is
  `400 INVALID_FILTER`) and compiled as the caller, so the export holds exactly
  the rows the caller's list shows.
- **Order**: the list's `sort` (default priority, severity, newest), with the
  id tie-breaker. All rows come from one read-only `REPEATABLE READ` snapshot,
  in batches of 1,000 with a 60 s statement timeout each.
- **Size**: at most 10,000 rows (`X-Export-Max-Rows`). The `X-Export-Truncated`
  and `X-Export-Rows` trailers say whether rows were left out. Larger exports are
  not offered yet: they need the background operations resource (research 230
  D10), and until then the caller narrows the filter.
- **Fields**: the `FindingExportRow` allowlist (41 columns, the same for CSV and
  NDJSON): identity, classification, scores, exploitation, SLA, asset id/name/type,
  location (file, lines, port, service), assignee, observation, validation and
  dates. Evidence (snippets, scanner output, stack traces, attachments, data
  flow), fix code, descriptions, free-form metadata and every secret detail are
  never exported. A unit test fails when the finding response gains a field
  without an export decision.
- **Permission**: `findings:export`. Without it the request is `403` with
  `details.missing_permissions: ["findings:export"]`; there is no partial
  export.
- **Concurrency**: one export per tenant and user across every API replica, a
  transaction advisory lock (`429` while one runs).
- **Audit**: every export is logged as `data.exported` with the row count, the
  cap, whether it was truncated, the format, the filter's field:operator shape
  and the sort (never filter values).
- CSV cells a spreadsheet would run as formulas are neutralized.
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
