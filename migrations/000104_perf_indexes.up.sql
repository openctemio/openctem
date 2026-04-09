-- =============================================================================
-- Migration 104: Critical performance indexes (audit follow-up)
-- =============================================================================
-- Adds two missing indexes identified by the database performance audit:
--
-- 1. idx_commands_step_run_id: CancelByPipelineRunID joins commands to
--    step_runs via step_run_id but commands had no index on that column,
--    causing a full table scan on every cancellation.
--
-- 2. idx_pipeline_runs_retry_eligible: ListPendingRetries filters on
--    completed_at within an exponential backoff window. The previous
--    partial index on (scan_id, completed_at) didn't fully match the
--    WHERE clause. This index covers the actual filter columns.

BEGIN;

-- 1. commands.step_run_id index for cancel cascade
CREATE INDEX IF NOT EXISTS idx_commands_step_run_id
    ON commands(step_run_id)
    WHERE step_run_id IS NOT NULL;

COMMENT ON INDEX idx_commands_step_run_id IS
    'Supports CancelByPipelineRunID JOIN — prevents full table scan on cascade cancel';

-- 2. Better retry eligibility index — covers status + retry_dispatched_at
--    + completed_at (the actual filter columns), ordered by completed_at
--    so the ORDER BY can use the index.
DROP INDEX IF EXISTS idx_pipeline_runs_retry_pending;

CREATE INDEX IF NOT EXISTS idx_pipeline_runs_retry_eligible
    ON pipeline_runs(completed_at ASC, scan_id)
    WHERE status = 'failed'
      AND retry_dispatched_at IS NULL
      AND completed_at IS NOT NULL;

COMMENT ON INDEX idx_pipeline_runs_retry_eligible IS
    'ScanRetryController polling — covers WHERE status=failed AND retry_dispatched_at IS NULL AND completed_at NOT NULL with ORDER BY completed_at ASC';

-- 3. Composite index for status list queries (audit issue #7)
--    Previous idx_pipeline_runs_status was (tenant_id, status) — adding
--    created_at lets ORDER BY use the index for paginated lists.
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_tenant_status_created
    ON pipeline_runs(tenant_id, status, created_at DESC);

COMMENT ON INDEX idx_pipeline_runs_tenant_status_created IS
    'Covers ListByTenantID with status filter and DESC sort';

COMMIT;
