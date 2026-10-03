-- RFC-042 slice 1: class facets and lens tabs filter assets by class within a
-- tenant. One statement per file: CREATE INDEX CONCURRENTLY cannot run inside
-- the implicit transaction of a multi-statement migration.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_asset_class ON assets (tenant_id, asset_class);
