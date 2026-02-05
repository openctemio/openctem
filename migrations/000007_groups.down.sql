-- =============================================================================
-- Migration 007: Groups and Access Control (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_groups_updated_at ON groups;
DROP TABLE IF EXISTS group_members;
DROP TABLE IF EXISTS groups;
