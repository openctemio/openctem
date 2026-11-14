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

- filled from `asset_recorded_addresses(asset_type, name, properties)`, the one definition of the rules above.
  It is a SQL function with a SQL-standard body (`BEGIN ATOMIC`) and no `SET` clause, so the planner inlines it
  into the calling statement, and every name in it is schema-qualified and bound when it is created: a
  caller's `search_path` cannot change what it calls. It is not `SECURITY DEFINER`;
- kept in step by triggers on `assets` (insert; update of the name, type, `deleted_at` or the three property
  keys), so every write path (the API, ingest, imports, merges) is covered; a deleted asset has no rows; an
  address that leaves the properties leaves the table in the same statement;
- the foreign key `(tenant_id, asset_id)` cascades on delete, and every read names the tenant; the table carries
  the tenant isolation policy (row level security in shadow mode) and is listed in
  `tools/lint/tenantsql/tenant_tables.txt`;
- an asset merge drops the merged assets' rows and recomputes the kept asset's from its row
  (`mergeAssetAddresses`, `internal/infra/postgres/asset_merge_plan.go`).

### Upgrade: the copy of the existing assets

The first migration only creates the table, the functions and the triggers: its lock on `assets` (for the
foreign key and the triggers) lasts milliseconds. The second, `20261114055218_asset_ip_addresses_backfill`, is
one statement, `CALL asset_ip_addresses_backfill(2000)`, so the runner sends it outside a transaction block
and the procedure commits after every batch of 2000 assets (by id):

- a batch locks its own rows `FOR SHARE` while it copies them (about a tenth of a second): a write to one of
  them waits for that batch, a write to any other asset never waits, and no table lock is taken;
- it reads each asset's current row (one changed since the batch began is re-read after the writer), and
  after the batch commits the triggers keep the asset in step;
- rows another transaction holds are skipped (`SKIP LOCKED`, so a batch never waits on or deadlocks with a
  writer) and copied in a final pass that waits for those writers;
- it only inserts (`ON CONFLICT DO NOTHING`), so rows the triggers wrote meanwhile stay, and running it again
  changes nothing; it ends with `ANALYZE asset_ip_addresses`.

Until it ends, a range filter can miss an asset that existed before the upgrade and was not written since.
On 1.35 million assets it took 137 s alone and 167 s while 2,900 asset writes a second went on (their
latency stayed at 1.4 ms on average; a probe write never waited more than 0.23 s), and the table then equalled a
full recompute.

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
range never reads another organization's rows.

### Query shape

`asset.AssetInRangesSQL(col, tenant, ranges...)` is `col IN (SELECT x.asset_id FROM asset_ip_addresses x WHERE
...)`, a semi join the planner sizes from the table's statistics:

- a wide range (`10.0.0.0/8`) walks the list's sort index (`idx_assets_created_at`,
  `idx_findings_tenant_priority_sort`) and probes the primary key `(tenant_id, asset_id, addr)` per row,
  stopping at the page;
- a narrow range (`/24`, one address) reads its few ids from `idx_asset_ip_addresses_range` first;
- several ranges (ORed by the filter compiler) become hashed subplans.

An array of ids (`col = ANY(ARRAY(...))`) is not used: the planner cannot size it, and on a wide range it built
every matching row (and its open-findings count) before cutting the page. The Assets list also reads a page's
ids before it joins the per-asset columns (`buildAssetPageQuery`, `internal/infra/postgres/asset_list_where.go`),
as the findings list does: under a member's data scope the planner otherwise computed the open-findings count
for every asset in scope first. A sort on the open-findings count keeps the one-statement form, since it needs
that count for every row.

`in_cidr` in `buildWhereClause` (smart group rules, `GET /assets?in_cidr=`) binds the tenant as `$1`; a filter
without a tenant matches nothing (no caller passes one).

Measured on 1.35 million assets and 5.45 million findings (one organization with 0.92 million assets):

| Query | Name only (before) | `ANY(ARRAY(...))` | Semi join + page ids first |
|---|---|---|---|
| Assets list `ip=10.0.0.0/8` | 17 ms | 5,550 ms | 2.7 ms |
| Assets list `ip=10.1.2.0/24` (few matches) | 1,554 ms | 0.4 ms | 0.5 ms |
| Assets list `/8`, member with a data scope | 237 ms | 2,137 ms | 6.3 ms |
| Assets list `/24`, member with a data scope | 246 ms | 0.5 ms | 0.5 ms |
| Findings list `asset_ip=10.0.0.0/8` | 1,318 ms | 3,451 ms | 2.3 ms |
| Findings count, 20 ranges | 1,432 ms | 580 ms | 1,433 ms |
| Smart group page (1000 ids), `/8` | 213 ms | 544 ms | 53 ms |

Pasting a range into a group (`POST /asset-groups/{id}/assets/paste`) uses the same condition. A value that is neither an address nor a range is a 400 naming
the parameter (the filter compiler); a smart group rule refuses it when saved.

Not covered: the inventory-mode CIDR target of a scan (`scan_selector_repository.go`) still selects only assets
named by an address, so the New Scan preview can count a host by recorded address that the scan does not target.

## Tests

- `internal/infra/postgres/asset_address_range_db_test.go`: the three filters agree; hosts by recorded address,
  `private_ip`/`public_ip`, network devices, IPv6, single addresses; a domain resolving into the range, a deleted
  asset, an address that left and another tenant's host never match; the plan reads an index of the table.
- `internal/infra/postgres/asset_ip_backfill_db_test.go`: the backfill copies assets written before the
  triggers, skips deleted ones and domains, keeps the rows the triggers wrote, and a second run changes nothing.
- `internal/infra/postgres/asset_list_page_db_test.go`, `asset_range_where_test.go`: list pages under a data
  scope match the whole list in order with the right counts, the open-findings sort still works, and
  `in_cidr` without a tenant matches nothing.
- `internal/infra/postgres/asset_ip_filter_db_test.go`, `asset_ip_tab_db_test.go`: exact ranges and the index.
- `internal/infra/http/routes/findings_asset_ip_db_test.go`, `data_scope_asset_in_cidr_db_test.go`: data scope
  and tenant through the API.
