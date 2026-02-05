-- =============================================================================
-- Migration 025: Threat Intelligence (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_threat_intel_sync_updated_at ON threat_intel_sync_status;
DROP TRIGGER IF EXISTS trigger_kev_catalog_updated_at ON kev_catalog;
DROP TRIGGER IF EXISTS trigger_epss_scores_updated_at ON epss_scores;

DROP TABLE IF EXISTS threat_intel_sync_status;
DROP TABLE IF EXISTS kev_catalog;
DROP TABLE IF EXISTS epss_scores;

