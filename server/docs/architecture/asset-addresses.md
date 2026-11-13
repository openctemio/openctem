# Asset addresses and range filters

Which IP addresses an asset has, and how a filter by address or range finds it.

## What counts as an asset's address

- **The name**, when the asset is an `ip_address`, or a `host` named by an address (`10.0.26.6`).
- **Recorded addresses of machines**: for `host` and `network` assets (and the legacy type names `compute`,
  `endpoint`, `firewall`, `load_balancer`), every address in the properties `ip_addresses` (the union of the
  current per-source addresses, kept by attribute reconciliation), `private_ip` and `public_ip`. A host named
  `web01.example.com` with `10.0.26.7` in `ip_addresses` has that address.
- **Not** the `ip_addresses` of a domain, subdomain, service or web application: those are what a name resolves
  to or what a service listens on, often a CDN or a shared front end, not an address the asset has. Use the
  `domain` filter (asset domain membership) for "everything that belongs to a name".

A value that is not one bare address (a range, a name, text, a number) is ignored. IPv4 and IPv6 both count.

## Where the addresses are kept

`asset_ip_addresses (tenant_id, asset_id, addr inet)`, migration `20261113075346_asset_ip_addresses`:

- filled from `asset_recorded_addresses(asset_type, name, properties)`, the one definition of the rules above;
- kept in step by triggers on `assets` (insert; update of the name, type, `deleted_at` or the three property
  keys), so every write path (the API, ingest, imports, merges) is covered; a deleted asset has no rows; an
  address that leaves the properties leaves the table in the same statement;
- the foreign key `(tenant_id, asset_id)` cascades on delete, and every read names the tenant; the table carries
  the tenant isolation policy (row level security in shadow mode) and is listed in
  `tools/lint/tenantsql/tenant_tables.txt`;
- an asset merge drops the merged assets' rows and recomputes the kept asset's from its row
  (`mergeAssetAddresses`, `internal/infra/postgres/asset_merge_plan.go`).

## The range condition

`asset.AssetIDsInRangesSQL(tenant, ranges...)` (`pkg/domain/asset/address_range.go`) is the only implementation.
It is used by:

| Filter | Where |
|---|---|
| Assets list `ip` (search box `ip=10.0.0.0/8`, saved views, MCP) | `pkg/domain/assetlist/fields.go` |
| Findings `asset_ip` (query language `asset.ip`) | `pkg/domain/vulnerability/finding_fields.go` |
| `GET /assets?in_cidr=` and smart asset group rules (`filter.in_cidr`) | `internal/infra/postgres/asset_repository.go` |

so a group rule and the list it was built from always agree. Each range is one btree range scan on
`idx_asset_ip_addresses_range (tenant_id, addr)`: stored addresses are full-mask, so
`addr BETWEEN host(network(r))::inet AND host(broadcast(r))::inet` is exact for `r` an address or a range, and
IPv4 ranges never reach IPv6 addresses (inet orders by family first). The tenant comes first in the index, so a
range never reads another organization's rows. The ids are read once (`col = ANY(ARRAY(...))`, an init plan), so
the matching assets or findings are then index lookups (`uq_assets_tenant_id_id`,
`idx_findings_tenant_asset_status`), also when several ranges are ORed.

Pasting a range into a group (`POST /asset-groups/{id}/assets/paste`) uses the same condition. A value that is neither an address nor a range is a 400 naming
the parameter (the filter compiler); a smart group rule refuses it when saved.

Not covered: the inventory-mode CIDR target of a scan (`scan_selector_repository.go`) still selects only assets
named by an address, so the New Scan preview can count a host by recorded address that the scan does not target.

## Tests

- `internal/infra/postgres/asset_address_range_db_test.go`: the three filters agree; hosts by recorded address,
  `private_ip`/`public_ip`, network devices, IPv6, single addresses; a domain resolving into the range, a deleted
  asset, an address that left and another tenant's host never match; the plan uses the index.
- `internal/infra/postgres/asset_ip_filter_db_test.go`, `asset_ip_tab_db_test.go`: exact ranges and the index.
- `internal/infra/http/routes/findings_asset_ip_db_test.go`, `data_scope_asset_in_cidr_db_test.go`: data scope
  and tenant through the API.
