-- =============================================================================
-- Migration 002: Users and Authentication (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_sessions_updated_at ON sessions;
DROP TRIGGER IF EXISTS trigger_users_updated_at ON users;

DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
