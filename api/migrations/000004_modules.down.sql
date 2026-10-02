-- =============================================================================
-- Migration 004: Modules (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_modules_updated_at ON modules;
DROP TABLE IF EXISTS modules;
