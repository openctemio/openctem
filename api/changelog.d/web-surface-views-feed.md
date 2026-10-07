### Added: web surface views, sensitive-path catalog, change feed and incremental template scans

- `GET /api/v1/web-path-patterns` (one path template across origins), `GET /api/v1/web-origins` (endpoints per origin
  with the coverage gap: excluded-untested, sensitive among them, sensitive answering without authentication),
  `GET /api/v1/web-endpoint-events` (appeared, returned, gone, status, auth, new parameter) and
  `GET /api/v1/web-path-catalog`. All within the tenant and the caller's data scope.
- Endpoints are labelled from a platform-curated sensitive-path catalog (`catalog_key`); `/web-endpoints/stats` reports
  `excluded_sensitive` and `unauth_sensitive`, and endpoints carry `exclusion_id` and their catalog entry.
- The change feed table `web_endpoint_events` (migration 001208). Retention: endpoints unseen 30 days become gone, gone
  for a year are deleted; events are kept 90 days.
- A template step chained after a crawl can take only the endpoints found new or changed in the run
  (`endpoint_selector: new | changed`). Design: RFC-056.
