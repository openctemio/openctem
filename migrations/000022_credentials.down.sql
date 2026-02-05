-- =============================================================================
-- Migration 022: Credentials (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_credentials_updated_at ON credentials;
DROP TABLE IF EXISTS credentials;

