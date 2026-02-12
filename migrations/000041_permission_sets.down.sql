-- =============================================================================
-- Migration 041: Permission Sets (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_permission_sets_updated_at ON permission_sets;
DROP FUNCTION IF EXISTS refresh_user_accessible_assets();
DROP TABLE IF EXISTS user_accessible_assets;
DROP TABLE IF EXISTS group_permission_sets;
DROP TABLE IF EXISTS permission_set_versions;
DROP TABLE IF EXISTS permission_set_items;
DROP TABLE IF EXISTS permission_sets;
