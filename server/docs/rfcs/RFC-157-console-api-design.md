# RFC-157: API design for the console

| | |
|---|---|
| Status | Proposed (2026-11-12). The session bootstrap, page views, the list contract base, the operation resource and the WebSocket are shipped; the reference catalog, lean list rows, keyset paging on large lists, facets, global search, bulk undo and the new live events are planned |
| Scope | server (endpoint shaping rules, bootstrap, reference catalog, list contract, views, operations, live events, budgets), web (how the console reads), docs |
| Architecture | [console-api-screens.md](../architecture/console-api-screens.md) (every screen and its data), [console-api-examples.md](../architecture/console-api-examples.md) (example bodies) |
| Related | RFC-041 (API paths and conventions), RFC-045 (WebSocket), RFC-048 (list query contract), RFC-115 (query language, the read layer), RFC-136 (page views and request budgets), [api-conventions.md](../architecture/api-conventions.md), [dashboards.md](../architecture/dashboards.md) |

## 1. Problem

The console is being redesigned screen by screen. Each new screen shows more on its first view (a figure strip,
tab counts, facets, a detail pane, live progress) and every block of it needs data. Left to itself, a screen
reads one endpoint per block: the finding page once sent about twenty requests, the asset page twelve, the
assets list nine. Each request pays the proxy hop, token checks, middleware, the data-scope guard and a token of
the per-user read limit, so many small reads make a page slow and can run a normal user into the limit.

The opposite mistake is just as costly: one big endpoint per screen mixes permissions, freshness and cost, so a
block the caller may not see or a slow block fails the whole screen, and every screen change becomes an API
change.

This RFC fixes how the console reads and writes: which standard the API follows, how a screen's blocks map to
endpoints, and the budgets each screen must meet. It applies to every screen of the redesigned console, to the
phone layout and to the platform admin console.

## 2. Goals and non-goals

Goals:

1. A screen's first view needs few requests: at most two shell reads on a hard load and three page reads.
2. Each block of a screen can fail, be refused or be refreshed on its own.
3. Authorization, tenant isolation and data scope are enforced once per endpoint, never re-implemented for a
   screen.
4. Lists stay fast at 100,000 findings or assets per organization and beyond.
5. One public contract serves the console, MCP tools, integrations, CI, extensions and third parties.

Non-goals:

- A query language for the browser. The browser sends typed requests; the structured filter document and the
  query language of RFC-115 stay behind typed list endpoints.
- A second API version. The contract stays `/api/v1` until 1.0.
- Server-side rendering of console screens.

## 3. Decisions

### 3.1 The standard

1. **Resource-oriented REST with an OpenAPI description stays the one contract.** Every read and write the
   console uses is a typed endpoint under `/api/v1` that other callers can use too.
2. **The server composes screens; the client does not.** Composition uses only the building blocks below:
   the session bootstrap, the reference catalog, page views, list companions (`include=`, facets), the WebSocket
   and the operation resource.
3. **Rejected alternatives.**
   - *A graph query language*, including persisted operations: authorization moves to every field resolver, cost
     and caching become per query, and it adds a second public surface next to the one MCP tools and
     extensions use. Page views give one request per screen with no new authorization code.
   - *A generic batch endpoint* (a client-chosen list of URLs): one request becomes many, arbitrary paths reach
     the internal dispatcher, and the response shape is unknowable (RFC-136).
   - *Caller-chosen fields* (sparse fieldsets): they bypass per-field checks and fragment caches. Collections
     have a fixed lean row instead (3.4).
   - *A separate per-screen aggregate service*: a second copy of authorization and tenant isolation to keep in
     step.
   - *Remote procedure calls with shared client types*: tied to one client language, of no use to MCP tools,
     extensions or third parties.
   - *Fetching on the web server* (server-side rendering): it splits the cache and duplicates token refresh,
     step-up and error handling for little gain over a view. Revisit only if first paint stays over budget.
   - *Connection multiplexing alone*: it removes the per-origin connection queue but not the per-request cost.
     It is enabled at the gateway as well, not instead.

### 3.2 Same endpoint or separate: the shaping rules

Two blocks of a screen MUST be served by the same response only when all of these hold; otherwise they MUST be
separate requests or separate parts of a view:

1. they describe the same object, or its fixed and bounded children (at most 1,000, in a stable order);
2. they need the same permission and module gate;
3. they have the same freshness class (3.9);
4. both are needed to draw the first view without a click;
5. the extra block costs less than a fifth of the main read and is bounded;
6. it is acceptable that both fail together.

Further rules:

- A block behind a tab, drawer, dialog, fold or hover MUST NOT be read before it is opened. A count shown on a
  tab label MUST come from a count field on the parent object, not from loading the tab.
- A detail page whose first view needs more than three reads SHOULD get a view (3.6).
- A list screen SHOULD read its list (with `include=` for tab counts), its facets and at most one figure strip,
  in parallel.
- Figures (dashboards, figure strips, sparklines, scores, changes against the previous period) MUST come from
  precomputed facts and carry `as_of`. They MUST NOT be computed on request.
- People MUST NOT be preloaded. Rows embed `{id, name}` references; pickers search.
- A sensitive value (secret, credential, personal data in evidence) MUST arrive masked. Showing it MUST be a
  separate, audited request, with step-up for secrets.

### 3.3 Shell bootstrap

`GET /api/v1/me/bootstrap` (shipped) is the one read every hard load makes: profile, memberships, permissions
and their version, modules, badge counts, pins, banners (announcements, ownership invitations, support access),
the AI setup summary and the limits flag. Each part follows the gate of the endpoint it replaces and is left out
when the caller fails that gate or its source errors.

Planned changes:

- add `reference_version` (3.5), the realtime channels the caller may subscribe to, and the Inbox total;
- move risk levels and SLA windows to the reference catalog;
- serve badge counts from per-user counters maintained in the background and push changes as events, instead of
  counting at request time.

The bootstrap MUST NOT carry lists, data only one screen needs, other people's data beyond the caller's own
memberships, secrets or tokens, or any count computed at request time over a large table.

### 3.4 List contract

Builds on RFC-048 (filters) and the reads section of [api-conventions.md](../architecture/api-conventions.md).

- **Lean rows (planned).** Each collection has one fixed row representation for lists: the fields a list,
  a peek and a phone row show, with `{id, name}` references. Long text, code snippets, scanner output and source
  data stay on the detail read. Today the findings list returns the full finding per row.
- **Keyset paging (planned).** Findings, assets, activity, audit, events, scan targets, the sensor fleet and
  the console's organization and user lists page with an opaque `cursor` and `next_cursor`, signed and bound to
  the tenant and the sort. Offset paging stays for small collections and stops at 10,000 rows.
- **Bounded totals (planned).** `total` is exact up to 10,000 rows; above that the list sends
  `total_is_estimate: true` and `estimated_total`. Later pages do not count again.
- **Tab counts.** `include=status_counts` (or the collection's equivalent) when there are at most about ten
  buckets on an indexed column, in the same scope as the rows. Shipped on scope and other lists.
- **Facets (planned for findings; shipped for assets).** `GET /{collection}/facets` with the same filters,
  sent in parallel with the list: top ten values per facet with counts capped at 10,000, `other_count` and
  `as_of`. Facets are separate because they aggregate the whole filtered set, may be slightly stale, and must not
  hold back the rows.
- **One filter grammar.** URL parameters, saved views, quick views, the command palette and the query engine
  share one filter document; the URL is a rendering of it, and `view=<saved view id>` applies a saved view on the
  server (shipped).
- **Empty is not an error.** An empty list answers 200 with `data: []` and `filters_applied`, so the console can
  tell "no data yet" from "no match" (planned field).

### 3.5 Reference catalog (planned)

`GET /api/v1/reference` returns the small tenant catalogs screens format with: finding statuses and
sub-statuses, priority classes, severities, risk levels, SLA windows, asset types and categories, finding kinds
and practices, teams (at most 1,000), tag names (at most 1,000, with `complete`), notification event types,
modules and finding sources. Labels are message keys plus the tenant's own names.

- Each section follows its source endpoint's permission; a section the caller may not read is absent.
- The response has an `ETag` over the tenant, the caller's permission version and the catalogs' versions, and
  `Cache-Control: private, no-cache`; the console keeps it for the session and revalidates with
  `If-None-Match`.
- A write to any source catalog publishes `reference.changed` on the tenant channel.

It replaces the separate catalog reads screens make today (asset types, event types, modules, tenant settings
for formatting, tags and teams for pickers).

### 3.6 Page views

Shipped (RFC-136): `GET /{resource}/{id}/view` answers a fixed, server-owned list of parts, each dispatched
through the router with the caller's credentials, so each part passes exactly its endpoint's gates. The object
is read first; a refused part keeps its status and error body and is absent from the page; the view is priced as
a fixed number of read tokens.

For the redesigned console:

- the finding view holds only what the first view shows; parts that only feed a tab move out, and their counts
  move onto the finding (planned);
- the asset view is finished the same way (planned);
- new views are planned for the scan run, the CTEM cycle, the sensor, the component and the pentest campaign
  detail pages;
- a peek drawer reads the lean row the list already holds plus the object itself, never the full view.

### 3.7 Dashboards

Shipped ([dashboards.md](../architecture/dashboards.md)): `GET /me/dashboards/home` returns the dashboard lists,
the landing dashboard and its widget results in one response; each widget result has a state (`ready`,
`not_measured`, `building`, `unsupported`, `error`), so one widget fails alone; every figure comes from
precomputed facts. Planned: a `range` parameter on the data routes and a per-widget read
(`?widget=<id>`) for refreshing one widget. The older live aggregate routes are removed with the screens that
call them.

### 3.8 Live updates

One WebSocket per tab (RFC-045, shipped) with channels authorized per subscription. Events tell the console what
changed; the console re-reads through REST, so the endpoint's gates apply again. Only run and operation progress
carry figures. Planned events: `badge.changed`, `scan_run.progress`, `operation.progress`, `finding.changed`,
`sensor.liveness`, `dashboard.refreshed` and `reference.changed`. Pages MUST NOT poll; while the socket is down a
page re-reads its visible blocks at most once a minute.

### 3.9 Freshness classes and caching

| Class | Examples | Server | Console |
|---|---|---|---|
| Static | widget catalog, permission catalog, filter schema | `ETag`, `private, no-cache` | kept for the session |
| Reference | statuses, SLA windows, teams, tenant settings | `ETag`, `private, no-cache` | kept for the session; dropped on own write or `reference.changed` |
| Working | lists, details, activity | `private, no-store` | reused for about 30 seconds; re-read on focus and after own write |
| Live | badges, run progress, sensor liveness | pushed | from events |
| Snapshot | dashboards, figure strips, scores | `private, no-store`, `as_of` in the body | as working; re-read on `dashboard.refreshed` |

No tenant response is ever stored by a shared cache: every one is `private` and varies on the credentials.
Writes return the updated object (or its lean row) and its `row_version`, so the console updates its cache
without a second read.

### 3.10 Bulk changes and long-running work

- **Preview first** for a selection by filter, for any change to scope, policy or approvals, and for more than 50
  items: `POST /{collection}/bulk/{verb}/preview` returns the count, a breakdown, warnings, a sample and a
  `preview_token` bound to the selection, the arguments, the tenant, the user and ten minutes (planned as a
  general pattern; findings by filter is shipped).
- **Apply** with the token or the selection and an `Idempotency-Key`. Up to 200 items answer inline with
  per-item results; more answer `202` with `Location: /api/v1/operations/{id}` (the operation resource is
  shipped).
- **Undo (planned).** An operation that changes status, assignment or tags keeps each item's prior values for 24
  hours; `POST /api/v1/operations/{id}/undo` restores them as a new operation, and an item changed again since is
  reported as skipped. Deletes are never undone this way: they stay soft deletes with their own restore.
- **Idempotency (planned for every operation-starting POST):** the key is honoured for 24 hours; the same key
  with another body is `422`, a duplicate while the first runs is `409`, and a replay carries
  `Idempotent-Replayed: true`.
- Exports and reports above 10,000 rows are operations with a signed, single-tenant download that expires in one
  hour.

### 3.11 Errors and partial results

- One error envelope `{code, message, request_id, details}` on the user and admin planes, as in
  [api-conventions.md](../architecture/api-conventions.md); the console picks its words from `code`. The sensor
  plane keeps RFC 9457 problem details.
- A refused block is absent, not an error: inside a view by its part status; outside a view by its own request.
- An aggregate that is not a view (bootstrap, reference catalog, dashboard batch, search, the Inbox summary,
  the console overview) answers 200 with the parts that succeeded and `errors: [{part, code, request_id}]` for the
  rest, so the screen can say "Could not load X" for that block only.

### 3.12 Search and the command palette

Planned: `GET /api/v1/search?q=&types=finding,asset,cve,scan&limit=5` returns the top matches per type. Each
type is gated by its own permission and module and searched inside the caller's data scope; a type the caller
cannot read is absent and no total is given for it. Navigation pages and settings rows are matched on the client
from the static navigation index. The palette's filter mode parses through the query endpoints (shipped) and
opens the list with the filter document.

### 3.13 Budgets

| Budget | Value |
|---|---|
| Requests at first view, hard load | shell 2 + page 3 |
| Requests at first view, moving between screens | page 3 |
| Requests in the 10 seconds after a page is quiet | 0 |
| List page of 50 lean rows, compressed | 60 KB |
| Detail view, compressed | 150 KB |
| Bootstrap / reference catalog, compressed | 15 KB / 40 KB |
| Server time p95: bootstrap / list page 1 (scoped, 1M findings) / facets / view / dashboard batch / single write | 150 / 300 / 500 / 400 / 200 / 300 ms |

The request budgets are enforced by the end-to-end request-budget gate (shipped for every page, including pages
with an id); the server budgets by the read-budget database test and by metrics alerts. A `Server-Timing` header
with coarse phases (application, database, view parts) is planned for console responses; it never names SQL,
ids or hosts.

### 3.14 Versioning and deprecation

The contract stays `/api/v1` until 1.0. A route only the old console used is removed in the same change that
removes its last caller and answers `410` for one release train. A route with outside callers is marked with
`Deprecation`, `Sunset` and a successor link for one release train first. A view's part list may change with its
screen without notice, because its parts are other endpoints.

### 3.15 Extensions and MCP tools

- MCP tools declare a permission and a module per tool (shipped). Every MCP tool that reads MUST have a REST
  equivalent with the same gate on the same read engine; no data is reachable only through MCP.
- Extensions mount their routes through the public extension API behind the same middleware chain, a declared
  permission and a grant (planned with the extension API). They follow this RFC's list contract and may add view
  parts only for their own routes.

## 4. Security requirements per endpoint kind

| Kind | Authorization | Tenant and data scope | Masking | Limits | Test that must exist |
|---|---|---|---|---|---|
| Bootstrap | each part the gate of the endpoint it replaces | the caller's own user and tenant | no secrets | one per hard load; read limit | a part behind a permission the caller lacks is absent |
| Reference catalog | each section its source endpoint's permission | tenant configuration only | no secrets | read limit; 200 KB cap | a member without the teams permission gets no teams; the ETag differs per permission set |
| View | each part through the router with the caller's credentials | object first; a refused object ends the view | each part's own masking | fixed parts, per-tenant concurrency, fixed read price | per new part: the part equals the direct read for a scoped member |
| List and facets | the list's permission | through the read engine in the caller's scope; never from organization-wide facts for a scoped caller | lean rows mask secret values | 100 rows per page; ten values per facet; counts capped; statement timeout | facet sums equal the scoped list total for a scoped member |
| Search | each type's permission and module | each type in the caller's scope, pentest visibility rule applied | secret titles masked | ten per type; query length 2 to 200; read limit | an out-of-scope asset searched by its exact name returns nothing and no count |
| Summaries (Inbox, needs attention, security overview, console overview) | each queue or area the permission of the list it opens | the caller's scope | | from counters or facts | each count equals the opened list's total for a scoped member |
| Operations | the creator or a holder of the operation kind's permission | the operation's tenant | downloads signed for one tenant and one hour | per-tenant budget | another tenant's operation is 404 |
| Reveal | its own permission, step-up for secrets | the object's scope | the only unmasked path | low per-user rate | every reveal writes an audit row |

General: an object outside the caller's tenant or data scope is `404`; responses carry `X-Request-ID`; the
per-user read limit stays as the security control and screens fit it by reading less; no client-chosen path
reaches the internal dispatcher; aggregates are capped at 1 MB with a logged truncation.

## 5. Rollout

Backend work lands one step ahead of the screens that need it:

1. Shell and shared: reference catalog, bootstrap changes and badge events, lean rows, keyset paging and bounded
   totals in the read engine, the facets pattern, global search, `Server-Timing`, the idempotency middleware.
2. Findings: findings facets, lean finding row, cursor, finding view trimmed to the first view, bulk preview,
   apply and undo, the Inbox's per-person state (done, snooze).
3. Assets, scoping and discovery: asset view finished, the needs-attention summary from facts, the scan run
   view and its progress events, new detail views.
4. Dashboards and insights: the range parameter and per-widget reads; reports and exports as operations.
5. Settings: the security overview as a snapshot, the reveal pattern, step-up on every governance write, `ETag`
   on settings reads.
6. Platform admin console: the overview from precomputed rows; keyset paging on organizations and users.
7. Phone layout: no new endpoints; the same rows with a smaller page size.

Each step removes the old routes its screens no longer call and lowers the request budgets of those screens.

## 6. Open questions

1. Lean list rows change the findings and assets list bodies inside v1. Proposed: change in place, list the
   removed fields in the changelog, since the console is the main caller and the detail read keeps every field.
2. One reference endpoint or per-catalog endpoints with `ETag`. Proposed: one endpoint.
3. Bulk undo scope. Proposed: status, assignment and tags of findings and assets; never deletes.
4. `Server-Timing` on console responses. Proposed: on, coarse phases only, controlled by a platform setting.
5. Fetching on the web server for the first view. Proposed: not now; measure again after the first three
   rollout steps.
