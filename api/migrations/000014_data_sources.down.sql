-- =============================================================================
-- Migration 014: Data Sources (Down)
-- =============================================================================

-- Drop FK constraint on assets first
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_source_id_fkey;

DROP TRIGGER IF EXISTS trigger_finding_data_sources_updated_at ON finding_data_sources;
DROP TRIGGER IF EXISTS trigger_asset_sources_updated_at ON asset_sources;
DROP TRIGGER IF EXISTS trigger_data_sources_updated_at ON data_sources;

DROP TABLE IF EXISTS finding_data_sources;
DROP TABLE IF EXISTS asset_sources;
DROP TABLE IF EXISTS data_sources;

DROP TYPE IF EXISTS source_status;
DROP TYPE IF EXISTS source_type;

