-- RFC-042 slice 1: lens tabs filter assets by lens within a tenant. One
-- statement per file: CREATE INDEX CONCURRENTLY cannot run inside the
-- implicit transaction of a multi-statement migration.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_asset_lens ON assets (tenant_id, asset_lens);
