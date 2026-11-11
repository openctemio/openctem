-- Network filter and group by network of the IP addresses tab
-- (network=10.1.2.0/24): ip_address assets by tenant and network.
--
-- Live impact: built CONCURRENTLY (no write lock on assets); partial, only
-- ip_address assets are indexed. The only statement in this file because
-- CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_ip_network ON assets (tenant_id, asset_ip_network(name)) WHERE asset_type = 'ip_address';
