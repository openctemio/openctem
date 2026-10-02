-- =============================================================================
-- Migration 011: Vulnerabilities (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_vulnerabilities_updated_at ON vulnerabilities;
DROP TABLE IF EXISTS vulnerabilities;
