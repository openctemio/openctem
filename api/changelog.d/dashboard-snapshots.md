### Added: stored dashboard snapshots, scheduled refresh and Refresh now

- Opening a dashboard now reads its stored snapshot instead of computing. A snapshot is computed on
  open only when there is none, when the layout changed, or, for a personal dashboard, when your access
  changed since it was computed (a snapshot of another scope is never shown).
- The `dashboard-snapshots` background job recomputes snapshots on each dashboard's refresh schedule
  (or the organization default); a failed refresh keeps the last good figures and marks them stale.
- `POST /api/v1/me/dashboards/{id}/refresh` and `POST /api/v1/organization/dashboards/{id}/refresh`
  ("Refresh now"): once a minute per person and dashboard, 30 an hour per organization (429 with
  `Retry-After`).
- Widget data responses carry `computed_at`, `refresh_schedule`, `next_refresh_at`, `stale` and
  `last_refresh_error`.
- Migration `003260_dashboard_snapshots` adds the tables `dash_snapshots` and `dash_refresh_requests`
  (new and empty; no upgrade step).
