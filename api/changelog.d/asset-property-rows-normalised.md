### Changed: stored asset properties normalised to the property schema (migration 001181)

- Migration 001181 folds the property synonyms of every stored asset into the canonical key: `ip`, `ips`, a plain `ip_address` string, `resolved_ip`, `resolved_ips` and `addresses` become `ip_addresses` (addresses in canonical form, non-addresses dropped; the technical `ip_address` object stays). `nameserver`, `technology` and `san` become `nameservers`, `technologies` and `sans`. It also removes keys that only other classes may hold, such as a port, HTTP status or banner on a domain, host or IP address (RFC-042 §6.3.9).
- `updated_at` is unchanged. Every changed row's previous properties are kept in `asset_properties_pre_001181`, which the down migration restores.
- **Upgrade note:** deploy the release that folds synonyms on write (#1311) with or before this migration. Run the migration explicitly; `air` does not run migrations.
