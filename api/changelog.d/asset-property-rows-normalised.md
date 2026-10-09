### Changed: stored asset properties normalised to the property schema (migration 001185)

- Migration 001185 folds the property synonyms of every stored asset into the canonical key: `ip`, `ips`, a plain `ip_address` string, `resolved_ip`, `resolved_ips` and `addresses` become `ip_addresses` (addresses in canonical form, non-addresses dropped; the technical `ip_address` object stays). `nameserver`, `technology` and `san` become `nameservers`, `technologies` and `sans`. It also removes keys that only other classes may hold, such as a port, HTTP status or banner on a domain, host or IP address (RFC-042 §6.3.9).
- `updated_at` is unchanged. The previous properties are kept only until migration 001481 drops the ledger; take a backup before upgrading if you may need them.
- **Upgrade note:** deploy the release that folds synonyms on write (#1311) with or before this migration. Run the migration explicitly; `air` does not run migrations.
