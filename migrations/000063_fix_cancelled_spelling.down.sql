-- =============================================================================
-- Migration 063 DOWN: Revert "canceled" → "cancelled"
-- =============================================================================

-- workflow_runs
UPDATE workflow_runs SET status = 'cancelled' WHERE status = 'canceled';
ALTER TABLE workflow_runs DROP CONSTRAINT IF EXISTS chk_run_status;
ALTER TABLE workflow_runs ADD CONSTRAINT chk_run_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'));

-- tool_executions
UPDATE tool_executions SET status = 'cancelled' WHERE status = 'canceled';
ALTER TABLE tool_executions DROP CONSTRAINT IF EXISTS chk_tool_executions_status;
ALTER TABLE tool_executions ADD CONSTRAINT chk_tool_executions_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'timeout', 'cancelled'));
