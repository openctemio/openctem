-- =============================================================================
-- Migration 102 DOWN: Revert Scan Phase 1 Improvements
-- =============================================================================

BEGIN;

-- Drop FK constraints
ALTER TABLE pipeline_runs DROP CONSTRAINT IF EXISTS fk_pipeline_runs_scan;
DROP INDEX IF EXISTS idx_pipeline_runs_scan;

ALTER TABLE scans DROP CONSTRAINT IF EXISTS fk_scans_last_run;

-- Drop check constraints
ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_timeout_seconds;
ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_agent_preference;

-- Drop columns
ALTER TABLE scans DROP COLUMN IF EXISTS timeout_seconds;

DROP INDEX IF EXISTS idx_scans_profile;
ALTER TABLE scans DROP COLUMN IF EXISTS profile_id;

ALTER TABLE scans DROP COLUMN IF EXISTS agent_preference;

COMMIT;
