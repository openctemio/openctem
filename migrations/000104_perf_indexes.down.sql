-- Migration 104 DOWN

BEGIN;

DROP INDEX IF EXISTS idx_pipeline_runs_tenant_status_created;
DROP INDEX IF EXISTS idx_pipeline_runs_retry_eligible;
DROP INDEX IF EXISTS idx_commands_step_run_id;

-- Restore the previous (less optimal) retry index for full reversibility
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_retry_pending
    ON pipeline_runs(scan_id, completed_at)
    WHERE status = 'failed' AND retry_dispatched_at IS NULL;

COMMIT;
