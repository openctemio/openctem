-- =============================================================================
-- Migration 032: Scans (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_scans_updated_at ON scans;

DROP TABLE IF EXISTS scans;
