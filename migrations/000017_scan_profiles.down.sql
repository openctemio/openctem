-- =============================================================================
-- Migration 017: Scan Profiles and Scan Sessions (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_scan_sessions_updated_at ON scan_sessions;
DROP TRIGGER IF EXISTS trigger_scan_profiles_updated_at ON scan_profiles;

DROP TABLE IF EXISTS scan_sessions;
DROP TABLE IF EXISTS scan_profiles;
