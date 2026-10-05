### Removed: the asset_sources table

- Migration 001070 drops `asset_sources`. Nothing ever wrote it (its
  repository was never constructed); production held 4 hand-made rows from one
  day with no source id and no contributed data. Its only reader, the asset
  lifecycle worker, now uses `assets.discovery_source` and `assets.last_seen`.
  The asset merge no longer moves its rows.
- Upgrade in one step. The down migration recreates the empty table.
