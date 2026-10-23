### Fixed: asset identity history lists only that asset's merges
- `GET /api/v1/assets/dedup/merge-log` accepts an optional `asset_id` (a UUID, otherwise 400) and returns only the events that kept or absorbed that asset, inside the caller's tenant and data scope. The asset drawer showed the tenant's latest merges and renames on every asset.
- `total` is now the number of matching events, not the number of rows returned.
