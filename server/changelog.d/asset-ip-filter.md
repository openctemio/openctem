### Added: filter findings by the address of their asset

- New findings filter `asset_ip` (one IP address or a CIDR range, e.g. `asset_ip=10.0.0.0/8`, up to 20 values) on `GET /findings`, `POST /findings/search`, stats and export, and `asset.ip` in the query language; assets queries take `ip`. It matches `ip_address` assets and needs `assets:read`, like other asset attributes.
- Migrations `20261107151034_asset_ip_function` (function `parse_asset_ip`) and `20261107151035_assets_ip_index` (partial index `idx_assets_ip_addr`, built concurrently; no table rewrite, no write lock).
- Filter fields can now be marked ordered (severity, priority class and asset criticality: an editor can offer "at least high") or as taking name patterns (asset name, asset domain).

### Changed: asset domain and asset name in queries need assets:read

- In the query language, `asset.domain` and `asset.name` (formerly written `asset_domain` and `asset_name`, which keep working) are asset attributes and need `assets:read`, like the other `asset.` fields.
