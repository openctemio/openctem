-- =============================================================================
-- Migration 063: Fix "cancelled" → "canceled" (American English) in constraints
-- =============================================================================

-- workflow_runs: fix chk_run_status
UPDATE workflow_runs SET status = 'canceled' WHERE status = 'cancelled';
ALTER TABLE workflow_runs DROP CONSTRAINT IF EXISTS chk_run_status;
ALTER TABLE workflow_runs ADD CONSTRAINT chk_run_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'canceled'));

-- tool_executions: fix chk_tool_executions_status
UPDATE tool_executions SET status = 'canceled' WHERE status = 'cancelled';
ALTER TABLE tool_executions DROP CONSTRAINT IF EXISTS chk_tool_executions_status;
ALTER TABLE tool_executions ADD CONSTRAINT chk_tool_executions_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'timeout', 'canceled'));
