### Added: findings filters by asset type, domain and name pattern

- `asset_type` / `asset_type_not`: findings on assets of the given stored types (`domain`, `subdomain`, `ip_address`, `service`, `repository`, ...).
- `asset_domain` / `asset_domain_not`: `example.com` is every finding on anything that belongs to the domain (its names, the addresses they resolve to, services on those addresses, certificates, web applications); `*.example.com` leaves the name itself out. CDN, edge and shared-hosting addresses never count. Membership is precomputed in `asset_domain_memberships` by the new `asset-domain-membership` worker from a queue that triggers fill (docs/architecture/asset-domain-membership.md).
- `asset_name` / `asset_name_not`: a name pattern (`*` any characters, `?` one), translated to an escaped match, never a regular expression.
- A filter takes at most two pattern or contains filters; a third is refused with a reason. A findings list that times out logs the names of its filter fields.
- The MCP `list_findings` tool takes `asset_type`, `asset_domain` and `asset_name`.
- Migration 20261106125549 adds the membership and queue tables and triggers, and queues every live asset once (no existing row changes).
