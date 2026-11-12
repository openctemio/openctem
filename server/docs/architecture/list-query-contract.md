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
4. Run `go run ./tools/gen/filterparams` and `make swagger` from `server/`: the
   `@Param` lines between `// filterspec-params:` markers are generated from
   the registry, and `TestOpenAPIDocumentsFilterParams` fails when the spec
   and the parser disagree.
5. The registry test fails on suffix-ending names, missing enums or ops the
   type cannot support. `TestFindingTemplatesPinTenant` fails when a findings
   template reads a tenant table without `{tenant}`.
6. A value that needs checking or a canonical form (a domain, a name pattern)
   gets `Normalize` (runs at parse time; its error is the reason returned) and,
   when one value binds several, `Expand` (runs at compile time; the result is
   still bound, never rendered). A pattern, contains or other costly leaf is
   `Expensive`: a filter takes at most `MaxExpensiveLeaves` (2) of them, and
   a third is refused with "narrow the filter".

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

### Asset filters of findings

| Param | Meaning | Served by |
|---|---|---|
| `asset_type`, `asset_type_not` | the stored type of the finding's asset (`domain`, `subdomain`, `ip_address`, `service`, `repository`, ...) | `(tenant_id, asset_type, ...)` index on assets |
| `asset_domain`, `asset_domain_not` | `example.com`: the name and every asset that belongs under it; `*.example.com`: only under it. Upper case, a trailing dot and Unicode labels are normalised; a bare public suffix (`com.vn`) is refused; up to 20 values | the `(tenant_id, key)` primary key of `asset_domain_memberships` ([asset-domain-membership.md](asset-domain-membership.md)) |
| `asset_ip` | the finding's asset is an `ip_address` asset inside an address or CIDR range (`10.0.0.0/8`, `2001:db8::/32`); up to 20 values; needs `assets:read` | `idx_assets_ip_addr (tenant_id, parse_asset_ip(name))`, one btree range per value ([database-notes.md](database-notes.md)) |
| `asset_name`, `asset_name_not` | a name pattern: `*` any characters, `?` one, everything else literal (`%`, `_` and `\` too); at most 3 wildcards, 200 characters, and a run of 3 literal characters; up to 10 values. Expensive | the trigram index on `assets.name` |

Every one is a tenant-pinned subquery that only narrows: the data scope, the
pentest visibility rule and the hidden-asset rule still apply to the list,
counts, groups, export, saved views and the MCP `list_findings` tool.

Measured on a scratch database with 100k findings and 50k assets per tenant
(two tenants): `asset_domain=<domain with 17k member assets>` counts 35k
findings in 16 ms and pages them in 52 ms; one host's domain 0.1 ms;
`asset_type=subdomain,repository` counts 40k findings in 19 ms;
`asset_name=*.<domain>` pages in 28 ms.

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
| `my_team` | `state=open&related_to=my_team` (+ `&informational=false`) |
| `my_due_soon` | `state=open&related_to=me&sla_deadline_lte=P3D` (+ `&informational=false`) |
| `my_accepted_expiring` | `status=accepted&acceptance_expires_at_lte=P30D&related_to=me` |
| `actionable` | `state=open&priority_class=P0,P1` |
| `known_exploited` | `state=open&is_in_kev=true` |

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

Fields added for the dashboard's closure quality widget
([dashboards](dashboards.md#closure-quality-campaigns-and-detection-quality)):
`resolved_by` (`is_null` only: whether a person closed the finding, never
who) and `last_reopened_at` (ranges; when a fixed finding last came back).

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

## Scans (`GET /scans`, `POST /scans/search`)

The scans list reads the `scans` registry (`pkg/domain/scan/scan_fields.go`).
A scan is tenant configuration (schedule, targets, tool), not an asset row, so
the registry is `Unscoped` (the reason is in the registry): the tenant
predicate is first, no data scope is added, and every caller with `scans:read`
sees the tenant's saved scans, exactly as before the migration. Fields:
`id`, `name` (a pattern with `*` and `?`, or `name_contains`), `status`,
`scan_type`, `schedule_type`, `sensor_preference`, `origin` (`user` or
`system`), `tag`, `asset_group_id` (the legacy single group and the list),
`scan_workflow_id`, `profile_id`, `scan_zone_id`, `scanner_name`,
`last_run_status`, `created_by`, `created_at`, `last_run_at`, `next_run_at`,
`total_runs` and `failed_runs`. `q` searches the name and the description.
Sortable: `name` (default), `created_at`, `last_run_at`, `next_run_at`,
`total_runs`.

Two rules are added by the server to every request, through registry fields a
request can not name (`archived`, `ad_hoc`): archived scans are never listed,
and quick scans that were never saved (`ad_hoc`) are listed only with
`include_ad_hoc=true` or when the request asks for `origin=system` at the top
level of its AND (the scans a platform policy manages are ad hoc by nature). A
`origin=system` inside an OR or a NOT lifts nothing. `include_ad_hoc` is a list
option, not a filter: `Options.Extra` on the route, a query parameter on
`POST /scans/search` too.

Old names: `search` (now `q`) and `tags` (now `tag`) are aliases with the
`Deprecation`, `Sunset` and `Warning` headers and the
`deprecated_query_param_requests_total` metric; `status`, `scan_type`,
`schedule_type`, `origin`, `asset_group_id`, `scan_workflow_id`, `sort`, `page`
and `per_page` are canonical names and need no alias. An unknown parameter is
now `400 INVALID_FILTER` (strict mode). `POST /scans/search` takes the
FilterDocument body with the same registry, permission (`scans:read`) and
rules. The query language has a matching `scans` entity
([query-language.md](query-language.md)).

## Scan runs (`GET /scan-runs`)

The tenant-wide runs list reads the `scan_runs` registry
(`pkg/domain/scanrun/run_fields.go`, `Unscoped` for the same reason). Fields:
`id`, `status`, `kind`, `trigger_type`, `scan_id`, `scan_workflow_id`,
`asset_id`, `origin` (`user` or `system`: the scan of the run is managed by a
platform policy, the scan pinned to the run's tenant on both sides),
`created_at`, `started_at`, `completed_at`, `duration` (seconds) and
`total_findings`; sortable by the time fields, `duration` and `total_findings`
(default `-created_at`). Rules added by the server: system runs are left out
unless `include_system=true` or the request names a `kind`, and a caller who
may not read findings does not see retest and validation runs. The old
parameters keep their names; an unknown parameter is `400 INVALID_FILTER`.

## Exposure items (`GET /attack-surface/exposures`)

The Exposure Items view reads `exposure_events` joined to its live asset
through the `exposure_items` registry (`pkg/domain/exposure/items.go`). The
filter is compiled from placeholder `$2`: `$1` is the tenant's
unclassified-scans mode, an input of the asset's monitoring state
(`asset_monitoring_state`, a lateral join added only when a filter or sort
reads it). The data scope applies to the exposure's asset; an exposure with no
asset is visible to unrestricted callers only. `category` filters by the
display category through a CASE over the event type built from the same map
as the row label. `/stats` (counts by severity, category and state) and
`/assets` (one row per asset) read the same WHERE. Details in
`exposure-taxonomy.md`, "Exposure Items view".

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

## Asset inventory (`GET /assets`, `POST /assets/search`)

The inventory reads its filter through the `assets` registry
(`pkg/domain/assetlist`), compiled as the caller: the tenant predicate, the
caller's data scope and the private program rule come first, then the
filter; soft-deleted assets never match. The registry holds every inventory
filter: the asset columns (`type`, `lens`, `criticality`, `exposure`,
`environment`, `provider`, `risk_score`, times...), the relations (`tag`,
`tag_all`, `technology`, `technology_category`, `business_unit`,
`asset_group`, `owner`, `domain`, `under`, `ip`) and the derived states
(`scope_status`, `monitoring_state`, `liveness`, `attribution`, `coverage`,
`coverage_cause`, `freshness`, `resolution`, `primary`, `program_assets`).
The derived states share their SQL with the other reads (dashboards,
exposure items), so a figure and the list it opens agree. Every template
that reads another table pins the caller's tenant.

- `name` is the exact name or a pattern (`api-*`); `name_contains` is a
  partial match. `technology` takes `name` or `name@version`. `domain` is
  domain membership (names, the addresses they resolve to, services and
  certificates, [asset-domain-membership.md](asset-domain-membership.md));
  `under` is the name itself at or below a DNS name.
- The tag fields count system tags of bug-bounty programs only for owners
  and members of the program (RFC-065 §15.3).
- `properties=key:value,...` (attribute filters) and `with_triage` are the
  list's own params beside the filter.
- The params the list took before (`types`, `criticalities`, `search`,
  `min_risk_score`, `tags` with `tags_mode=all`, ...) are aliases until
  2026-12-20 (`Deprecation`, `Sunset`, `Warning`).
- Counts stop at 10,000: `total` is exact up to it, and above it
  `total_capped` is true. Offsets stop at 10,000 too; `cursor` (empty for the
  first page) pages in `last_seen desc, id desc` order with `next_cursor` and
  no depth limit. A cursor carries a position only, never a tenant or scope.
- `network` (the /24 of IPv4, the /64 of IPv6, `asset_ip_network`, index
  `idx_assets_ip_network`), `port` and `service` (open ports,
  [asset-ports.md](asset-ports.md)) filter the IP addresses tab. Every
  address row carries `ip`: its network, up to 3 names resolving to it and up
  to 5 open ports, with totals, counting only names and ports in the
  caller's scope. `GET /assets/networks` groups the matching addresses by
  network (at most 500).
- `?view=<id>` runs a saved view of the `assets` page as the caller.
- The asset inventory page (web) sends only these names. Its own URL keeps
  the page's older params (`types`, `criticalities`, `tags`...) so no link
  breaks, and carries the fields it has no control for (`ip`, `network`,
  `port_gte`...) under the names above. Inside the External surface lens
  (`?lens=external_surface`) the type is a tab (`?tab=ip_address`): a locked
  `type` condition that is not part of the editable query text; an old
  `types=<one type>` link opens the matching tab. The Query toggle edits the
  same filter as text: a filter the chips can show is written back as flat
  params, any other (an OR across fields, a group) is kept whole as `fq` and
  runs as the document `POST /query/parse` made of it, through
  `POST /assets/search`; the page never sends the text to a list endpoint.
  Saved views of the `assets` page store the list's params, or the checked
  document of an `fq` filter, with the tab's type. "Group by network" lists
  `GET /assets/networks` for the same params (not for an `fq` filter), and
  every total shows "10,000+" when `total_capped` is true.
- List and count run in one read-only transaction under a 5 s statement
  timeout.

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

## Text query (search boxes)

A search box may hold the short form of the query language
(`severity>=high kev=true -status:accepted`, [query-language.md](query-language.md#short-form-search-boxes)).
The list endpoints never receive the text: the page sends it to
`POST /api/v1/query/parse`, which answers the version 1 filter document (and,
when every condition is a chip, the flat params). A filter chips can show
stays in today's flat params, so links keep their form; one they cannot (an
OR across fields, a group) is `fq=<canonical text>` in the page URL, and the
page sends its document to `POST /findings/search`. Requests that cannot
carry it (stats, export, bulk by filter) fail closed: an `fq` param is an
unknown param (400), never a wider read.

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
characters per value (`q` 255), 32 KB POST body, 2 expensive leaves (pattern,
contains). List and count statements run under a 5 s statement timeout; a
timeout is a 503 `QUERY_TIMEOUT` ("narrow the filter").

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
  `/findings`, `/findings/stats`, `/findings/groups`, `/findings/export` and
  `/assets` (page `assets`, needs `assets:read`) compiles the view's filter as the caller, with the request's own params
  overriding it field by field (`filterspec.Overlay`). Sharing a view shares
  a query, not anyone's rows.
- Every read and write is tenant-bound; a view the caller may not see (or of
  another tenant) is 404. Changes are audit-logged (`saved_view.*`).
