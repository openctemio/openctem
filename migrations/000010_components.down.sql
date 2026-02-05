-- =============================================================================
-- Migration 010: Components (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_asset_components_updated_at ON asset_components;

DROP TABLE IF EXISTS licenses;
DROP TABLE IF EXISTS asset_components;
