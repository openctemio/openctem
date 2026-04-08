-- =============================================================================
-- Migration 103: Performance Indexes for Scan Phase 1
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds missing indexes identified by performance audit:
--   1. idx_scans_last_run - prevents full-table scan on pipeline_run delete
--   2. idx_pipeline_runs_pending_started - optimizes scan timeout sweeper query
--   3. drops idx_scans_profile (unused — no query filters by profile_id)

-- Note: We CANNOT use CREATE INDEX CONCURRENTLY inside a transaction.
-- For migration safety we accept brief lock time on small/medium tables.
-- For very large tables, run these manually with CONCURRENTLY before deploying.

BEGIN;

-- 1. Index on scans.last_run_id to support FK referential integrity check
--    when deleting pipeline_runs (otherwise full table scan of scans).
CREATE INDEX IF NOT EXISTS idx_scans_last_run
    ON scans(last_run_id)
    WHERE last_run_id IS NOT NULL;

COMMENT ON INDEX idx_scans_last_run IS
    'Supports FK constraint check during pipeline_run deletion (added by migration 103)';

-- 2. Partial index on pipeline_runs(started_at) for the timeout sweeper.
--    The sweeper filters: status IN ('pending','running') AND started_at IS NOT NULL
--    AND EXTRACT(EPOCH FROM (NOW() - started_at)) > scan.timeout_seconds
--    This index lets PostgreSQL quickly find candidate rows without scanning all runs.
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_pending_started
    ON pipeline_runs(started_at)
    WHERE status IN ('pending', 'running') AND started_at IS NOT NULL;

COMMENT ON INDEX idx_pipeline_runs_pending_started IS
    'Optimizes ScanTimeoutController sweeper query (added by migration 103)';

-- 3. Drop unused profile_id index — no query in the codebase filters by profile_id.
--    The column is only read alongside the rest of the scan row.
--    Removing the index reduces write overhead on scan updates.
DROP INDEX IF EXISTS idx_scans_profile;

-- 4. Retry config columns for Phase 2.3 retry logic
ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS max_retries INTEGER NOT NULL DEFAULT 0;

ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS retry_backoff_seconds INTEGER NOT NULL DEFAULT 60;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_scans_max_retries'
    ) THEN
        ALTER TABLE scans ADD CONSTRAINT chk_scans_max_retries
            CHECK (max_retries >= 0 AND max_retries <= 10);
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_scans_retry_backoff'
    ) THEN
        ALTER TABLE scans ADD CONSTRAINT chk_scans_retry_backoff
            CHECK (retry_backoff_seconds >= 10 AND retry_backoff_seconds <= 86400);
    END IF;
END $$;

COMMENT ON COLUMN scans.max_retries IS
    'Maximum number of automatic retry attempts after a run fails (0 = no retry, max 10)';
COMMENT ON COLUMN scans.retry_backoff_seconds IS
    'Initial backoff seconds between retries — actual delay uses exponential backoff (min 10, max 86400)';

-- 5. retry_attempt column on pipeline_runs to track current attempt number
ALTER TABLE pipeline_runs
    ADD COLUMN IF NOT EXISTS retry_attempt INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN pipeline_runs.retry_attempt IS
    'Current retry attempt number (0 = first attempt, 1 = first retry, ...)';

COMMIT;
