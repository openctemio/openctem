### Changed: the web console sends one request per identical GET in flight

- Two parts of a page that read the same URL at the same time (under different
  cache keys, or a direct read racing a hook) now share one request. In
  development, a GET sent twice at once or repeated within a second logs a
  `[request-budget]` warning naming the URL.
- A guard test (`request-hygiene-guard.test.ts`) counts raw `fetch` of the API
  outside the API layer, `[url, tenantId]` cache keys and polling sites; the
  counts only go down (research/81, page-load request budget).
