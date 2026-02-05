-- =============================================================================
-- Migration 008: Assets (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_assets_updated_at ON assets;

DROP TABLE IF EXISTS asset_owners;
DROP TABLE IF EXISTS assets;

-- Note: asset_groups and asset_group_members are dropped in 000024_asset_groups.down.sql

