-- =============================================================================
-- Migration 108 (down): drop the relationship type aggregation index.
-- =============================================================================

DROP INDEX IF EXISTS idx_asset_relationships_tenant_type;
