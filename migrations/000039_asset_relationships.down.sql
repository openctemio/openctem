-- =============================================================================
-- Migration 000039: Asset Relationships (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_asset_relationships_updated_at ON asset_relationships;
DROP TABLE IF EXISTS asset_relationships;
