-- =============================================================================
-- Migration 043: Admin Users & Audit Logs (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_admin_users_updated_at ON admin_users;
DROP TABLE IF EXISTS admin_audit_logs;
DROP TABLE IF EXISTS admin_users;
