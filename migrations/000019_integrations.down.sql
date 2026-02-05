-- =============================================================================
-- Migration 019: Integrations (Down)
-- =============================================================================

-- Drop FK constraint on assets first
ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_integration_id_fkey;

DROP TRIGGER IF EXISTS trigger_integrations_updated_at ON integrations;

DROP TABLE IF EXISTS integration_notification_extensions;
DROP TABLE IF EXISTS integration_scm_extensions;
DROP TABLE IF EXISTS integrations;

