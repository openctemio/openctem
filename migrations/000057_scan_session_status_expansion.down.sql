-- =============================================================================
-- Migration 000057 DOWN: Revert Scan Session Status Expansion
-- =============================================================================

DROP INDEX IF EXISTS idx_scan_sessions_status;

-- Migrate back 'canceled' → 'canceled', remove 'queued'/'timeout'
UPDATE scan_sessions SET status = 'failed' WHERE status = 'timeout';
UPDATE scan_sessions SET status = 'pending' WHERE status = 'queued';
UPDATE scan_sessions SET status = 'canceled' WHERE status = 'canceled';

ALTER TABLE scan_sessions DROP CONSTRAINT IF EXISTS chk_scan_sessions_status;
ALTER TABLE scan_sessions ADD CONSTRAINT chk_scan_sessions_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'canceled'));
