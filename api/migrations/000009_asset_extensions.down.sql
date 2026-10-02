-- =============================================================================
-- Migration 009: Asset Extensions (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_asset_services_updated_at ON asset_services;
DROP TRIGGER IF EXISTS trigger_repository_branches_updated_at ON repository_branches;

DROP TABLE IF EXISTS asset_state_history;
DROP TABLE IF EXISTS asset_services;
DROP TABLE IF EXISTS repository_branches;
DROP TABLE IF EXISTS asset_repositories;
