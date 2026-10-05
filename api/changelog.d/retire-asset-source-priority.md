### Removed: asset source priority (RFC-003) and the data_sources registry

- RFC-003 is withdrawn: no ingest path ever called its priority gate and
  nothing wrote `data_sources`, so the per-organization priority and
  trust-level settings configured a no-op. Removed:
  `GET/PUT /api/v1/tenants/{tenant}/settings/asset-source`, the `asset_source`
  settings section (and its key in `tenants.settings`), the ingest priority
  gate and trust levels, and `pkg/domain/datasource`.
- The `drop_data_sources` migration drops `data_sources` (0 rows), the `source_status` enum and
  the never-used `assets.source_id` / `assets.source_ref` columns.
- Upgrade in one step. A client that still calls the asset-source settings
  endpoints gets 404. The down migration recreates the empty table and
  columns.
