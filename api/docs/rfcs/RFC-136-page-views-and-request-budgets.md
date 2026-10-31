# RFC-136: Page views and request budgets

| | |
|---|---|
| Status | Accepted (2026-10-29). The finding and asset page views and the budget for pages with an id shipped; other pages follow one by one |
| Scope | api (view endpoints on one shared part dispatcher), web (primed answers for a page's own reads, the request budget gate, one toast per error code), docs |
| Architecture | [page-views.md](../architecture/page-views.md) |
| Related | RFC-115 (query language, the read layer), RFC-045 (WebSocket), [dashboards.md](../architecture/dashboards.md) (`GET /dashboard/overview`, the first view) |

## 1. Problem

Each panel of a page reads its own endpoint. The finding page sent about twenty requests on every
finding: the finding, its AI triage and the tenant's AI setup, watchers, ticket links and holds,
verification, retest check and retests, approvals, remediation tasks, issue links, identity, imports,
activity, comments, and two evidence lists. Stepping through findings spent the per-user read limit
(120 a minute) within six findings: the page showed "Could not load this finding" and stacked
"Too many requests" toasts. The request budget gate (`web/e2e/request-budget.json`) checked only pages
without an id in their path, so nothing counted it.

## 2. Decisions

1. **A page that needs many reads on load gets one view endpoint**, `GET /<resource>/{id}/view`
   (the finding page first). The view answers a fixed list of parts, keyed by the exact URL the web
   asks for each one, with each endpoint's status and body.
2. **Every part is answered by the endpoint itself.** The view sends each part's GET through the API's
   own router with the caller's credentials (Authorization and Cookie only), so a part passes exactly
   its endpoint's gates: authentication, tenant, permission, module and data scope.
   The view adds no authorization logic of its own, and so cannot drift from the endpoints.
3. **A refused part is absent, not a failure.** It carries its own status and error code (a missing
   permission, a module that is off) and no data; the view still answers 200 with every other part.
   A server failure carries its status and no body.
4. **The object is read first.** Unless it answers 200 (missing, out of scope, another tenant's), the
   view holds only that answer: a bad id costs one read, and no other part runs for it.
5. **Only the server chooses paths.** The id is parsed as a UUID and only the view's own list is
   dispatched. There is no generic batch endpoint: a client-chosen list of URLs would turn one request
   into many and route arbitrary paths through the internal dispatcher.
6. **The web keeps its panels.** The page asks for the view on its first load of each object and primes
   the answers; the browser's `fetch` answers a same-origin GET for a primed URL once, within ten
   seconds, instead of sending it. Every panel and hook still reads its own URL and gets exactly its
   endpoint's answer. Later reads (a refresh after a save) go to the endpoint. A failed view falls back
   to the panel reads.
7. **One shared dispatcher.** `GET /dashboard/overview` and every view use the same part dispatcher
   (bounded parts per tenant, identical concurrent requests share one computation, optional per-caller
   reuse; the finding view computes every request).
8. **Every page has a request budget**, pages with an id included: `request-budget.json` lists each
   such page under `dynamicRoutes` with the list that gives a sample id, and the e2e gate fails a page
   that is missing, over its budget, or sends a request twice.
9. **The read limit is a security control and stays as it is.** Pages fit it by sending fewer
   requests, never by a higher limit or automatic retries. A view is priced as a fixed number of reads
   (the finding view: 3 tokens of the per-user budget, its own request included) and its parts take
   nothing more: they are marked as view parts in a context only server code can set. A view the budget
   cannot cover is refused (429) before any part runs.
10. **One toast per error code.** A burst of refused reads shows one "Too many requests" toast, not one
   per panel.

## 3. Threat model

- **Assets:** findings and their related records, across tenants and across data scopes inside a
  tenant.
- **Actors:** a member with a narrow scope or a narrow role, a member of another tenant, a stolen
  session.
- **Abuse cases and answers:**
  - *A panel the caller may not read leaks through the view.* Every part runs through its endpoint's
    own gates with the caller's own credentials; the routes test compares each part with the direct
    read for a scoped member.
  - *Another tenant's or an out-of-scope finding is probed through the view.* The finding is read first,
    with the same answer as the direct read (404); nothing else is dispatched; tests cover both cases.
  - *Path injection into the dispatcher.* The id must parse as a UUID; the parts are a fixed list built
    from the canonical id; the view's query string is ignored.
  - *Amplification.* One view runs a fixed number of parts (17 for a finding), bounded per tenant (8
    at a time), and costs a fixed 3 tokens of the caller's read budget, charged before any part runs; a
    bad id costs one dispatched read. A scraper gets at most 40 finding views a minute per user under
    the default budget. The view-part mark that spares the parts a token lives in the request context,
    which no client can set.
  - *Identity confusion.* A part gets a fresh context; it authenticates from the forwarded credentials
    alone, and no client header (X-Forwarded-For) is forwarded.
  - *A primed answer served to the wrong session.* Primed answers live in the tab's memory, are used
    once, expire after ten seconds and are dropped on an organization switch.
  - *Cache.* The response is `Cache-Control: private, no-store`; the finding view is never reused
    between requests.

## 4. Rollout

1. The finding page view and the budget for pages with an id (this RFC's first change).
2. One page at a time, worst first, from the measured table in the research note: the page gets a view
   when its first screen needs more than a few reads, or its panels load on demand when they are below
   the fold or behind a tab. Each change lowers that page's budget.
3. Tenant configuration that every page reads goes into `/me/bootstrap` or the `SWR_REFERENCE` cache
   class, never a request per page.
