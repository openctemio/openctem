-- =============================================================================
-- Migration 030: Capabilities (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_capabilities_updated_at ON capabilities;

DROP TABLE IF EXISTS tool_capabilities;
DROP TABLE IF EXISTS capabilities;

