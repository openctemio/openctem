-- Address filter of the search box (ip=10.0.0.0/8): ip_address assets by tenant and
-- address. A range filter compiles to a btree range on this index
-- (parse_asset_ip(name) BETWEEN the first and the last address of the range).
--
-- Live impact: built CONCURRENTLY (no write lock on assets); partial, only
-- ip_address assets are indexed. The only statement in this file because
-- CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_ip_addr ON assets (tenant_id, parse_asset_ip(name)) WHERE asset_type = 'ip_address';
