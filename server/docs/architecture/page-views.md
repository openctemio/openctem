# Page views and request budgets

Design: [RFC-136](../rfcs/RFC-136-page-views-and-request-budgets.md).

A page of the web console that needs many reads on load asks for them in one response, a **view**,
and every page has a **request budget** that the e2e gate enforces.

| Part | Status |
|---|---|
| Shared part dispatcher (`handler/view_parts.go`), used by `GET /dashboard/overview` | **Shipped** |
| `GET /api/v1/findings/{id}/view` and the finding page on it | **Shipped** |
| `GET /api/v1/assets/{id}/view` and the asset page on it | **Shipped** |
| Primed answers in the browser (`web/src/lib/api/view-prime.ts`) | **Shipped** |
| Request budget for pages with an id in their path (`dynamicRoutes`) | **Shipped** |
| Views or on-demand panels for the other heavy pages (scan, remediation task, campaign) | Planned, one page at a time |

## How a view answers

`GET /api/v1/findings/{id}/view` (permission `findings:read`):

1. The view takes its read cost (3 tokens) from the caller's budget, or answers 429 before any part
   runs. The id must parse as a UUID (400 otherwise); every part URL is built from its canonical form.
2. The finding itself, `GET /api/v1/findings/{id}`, is dispatched first. Unless it answers 200, the
   response holds only that part: a missing finding, one outside the caller's data scope and another
   tenant's all give the same 404 the endpoint gives, and nothing else runs.
3. The other parts (`FindingViewParts`) are dispatched in parallel, at most eight at a time per tenant.
4. The response is `{"parts": {"<url>": {"status": 200, "body": {...}}}}`, `Cache-Control: private,
   no-store`.

Each part is sent through the API's own router with only the caller's `Authorization`, `Cookie` and
`Accept-Language`, in a fresh context. It passes its endpoint's own middleware: authentication, tenant,
permission sync, the module gate and the data-scope guard; the per-user read limit was paid by the
view's own request. A part the caller
may not read keeps its own status and error body (for example `403 FORBIDDEN` or `403
MODULE_NOT_ENABLED`) and no data, and the view still answers 200. A part that fails with 5xx carries
its status and no body, and is logged without ids.

`GET /dashboard/overview` uses the same dispatcher with a 15-second per-caller reuse and four parts at a
time per tenant; it keeps no error bodies.

## The asset view

`GET /api/v1/assets/{id}/view` (permission `assets:read`) works the same way: the asset,
`GET /api/v1/assets/{id}`, is read first and a refusal ends the view; the parts are the asset page's
panels (attribution, attribute sources, freshness, coverage, identifiers, renames, the change timeline,
web evidence, the ports on a name's resolved addresses and the discovery lineage), listed in `AssetViewParts`. The view costs
3 read tokens. `useAssetPage` (in `features/assets/hooks/use-assets.ts`) primes it on the page's first
load of each asset. The scan window card asks with a `POST` and is not a part.

## How the web uses a view

`useFindingPageApi` (in `features/findings/api/use-findings-api.ts`) loads the finding page's finding.
On the page's first load of each finding it asks for the view and calls `primeView`, then reads the
finding as before. `installPrimedFetch` (in `instrumentation-client.ts`) wraps `window.fetch`: a
same-origin `GET` whose path and query equal a primed part is answered from it, once, within ten
seconds. Only 200, 403 and 404 answers are primed, so a 401 still reaches the token refresh and a
server failure is still retried. The panels and hooks are unchanged: each reads its own URL and gets
its endpoint's answer. A save that revalidates a panel reads the endpoint. If the view fails, the
panels read their endpoints as before. An organization switch drops every primed answer
(`clearSwrCache`).

To give another page a view:

1. Add `<Resource>ViewParts(id)` and a handler on `newViewParts`, and register the route with the
   resource's read permission.
2. List the exact URLs the page's hooks fetch (path and query, in the same parameter order). The routes
   test compares each part with the direct read, so a URL that drifts shows up as a part the page does
   not use, and the page's budget catches the extra request.
3. Load the page's object through a hook that primes the view on first load, as `useFindingPageApi`
   does.
4. Lower the page's entry in `web/e2e/request-budget.json`.

## Request budgets

`web/e2e/request-budget.json` holds the most API requests a hard load of each page may send:

- `routes` for pages without an id (`defaultMax` when a page is not listed);
- `dynamicRoutes` for every page with an id in its path: the list that gives a sample id (`sample`,
  `field`) and the budget (`max`). Every such page must be listed.

`web/e2e/specs/16-request-budget.spec.ts` loads each page and fails when a page sends more than its
budget, sends one request twice, sends `/me/bootstrap` other than once, or asks for a session read that
`/me/bootstrap` carries. Raising a budget needs a reviewer to agree that the new request cannot come
from the bootstrap, the cache, an event or the page's view.

## Read limit

The per-user limit for authenticated `GET` requests (`RATE_LIMIT_READ_PER_MIN`, 120 a minute) is a
security control and is not raised for pages. A view costs a fixed number of tokens (the finding view
3, the dashboard overview 6), charged on its own request before any part runs; its parts are marked as
view parts in their server-set context (`middleware.WithViewPart`) and take no token of their own.
Pages fit the limit by asking for less (D5 and D6 of the research note: no request for content behind a
click, tenant configuration from the bootstrap or the cache). A burst of refused reads shows one toast.

## Key files

- `api/internal/infra/http/handler/view_parts.go`: the dispatcher.
- `api/internal/infra/http/handler/finding_view_handler.go`: the finding view and its parts.
- `api/internal/infra/http/handler/asset_view_handler.go`: the asset view and its parts.
- `api/internal/infra/http/routes/asset_resolved_ports_db_test.go`: asset view parts, resolved ports scope and tenant.
- `api/internal/infra/http/handler/dashboard_overview_handler.go`: the dashboard overview.
- `api/internal/infra/http/routes/finding_view_scope_db_test.go`: parts equal the direct reads, scope and tenant.
- `web/src/lib/api/view-prime.ts`: primed answers.
- `web/e2e/request-budget.json`, `web/e2e/specs/16-request-budget.spec.ts`: the budget gate.
