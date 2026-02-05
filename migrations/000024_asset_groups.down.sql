-- =============================================================================
-- Migration 024: Asset Groups (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_asset_groups_updated_at ON asset_groups;

DROP TABLE IF EXISTS asset_group_members;
DROP TABLE IF EXISTS asset_groups;

