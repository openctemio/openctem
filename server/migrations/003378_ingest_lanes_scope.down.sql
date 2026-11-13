-- Reverts 003363_ingest_lanes_scope.
DROP INDEX IF EXISTS ix_ingest_jobs_pending_lane;
DROP INDEX IF EXISTS ux_ingest_jobs_scope_running;
ALTER TABLE ingest_jobs DROP CONSTRAINT IF EXISTS chk_ingest_jobs_lane;
ALTER TABLE ingest_jobs
    DROP COLUMN IF EXISTS scope_key,
    DROP COLUMN IF EXISTS lane;
