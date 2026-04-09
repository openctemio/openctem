-- =============================================================================
-- Migration 103 DOWN: Revert Phase 1.8 Performance Indexes
-- =============================================================================

BEGIN;

DROP INDEX IF EXISTS idx_pipeline_runs_retry_pending;
ALTER TABLE pipeline_runs DROP COLUMN IF EXISTS retry_dispatched_at;
ALTER TABLE pipeline_runs DROP COLUMN IF EXISTS retry_attempt;

ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_retry_backoff;
ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_max_retries;
ALTER TABLE scans DROP COLUMN IF EXISTS retry_backoff_seconds;
ALTER TABLE scans DROP COLUMN IF EXISTS max_retries;

DROP INDEX IF EXISTS idx_pipeline_runs_pending_started;
DROP INDEX IF EXISTS idx_scans_last_run;

-- Restore the unused profile_id index for full reversibility
CREATE INDEX IF NOT EXISTS idx_scans_profile ON scans(profile_id) WHERE profile_id IS NOT NULL;

COMMIT;
