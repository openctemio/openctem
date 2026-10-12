### Fixed: the asset lifecycle worker demotes assets ingest stopped seeing

- The stale pass required a row in `asset_sources` before it would demote an
  asset. Nothing writes that table, so an enabled worker never marked any
  discovered asset stale. It now decides from the asset itself: the clock is
  `assets.last_seen` (moved only by ingest and integrations) and the
  provenance is `assets.discovery_source`, mapped to the categories of the
  "excluded source types" setting (manual, import, integration, scanner; an
  asset with no discovery source counts as manual). A raw discovery source
  (for example `cert_transparency`) can also be excluded on its own.
- Tenants that enabled the worker will see ingest-discovered assets that were
  not re-observed within the threshold go stale on the next run. Run the
  dry-run first to preview the count. The worker is off by default.
