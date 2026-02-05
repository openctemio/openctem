-- =============================================================================
-- Migration 001: Extensions and Helper Functions (Down)
-- =============================================================================

DROP FUNCTION IF EXISTS cleanup_old_audit_logs(INTEGER);
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP TYPE IF EXISTS user_status;
