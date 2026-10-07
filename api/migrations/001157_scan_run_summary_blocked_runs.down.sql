-- Blocked runs become failed runs (the status the old code knows), with the
-- refusal code kept in the message.
UPDATE pipeline_runs
SET status = 'failed',
    error_message = COALESCE(refusal_code || ': ', '') || COALESCE(error_message, '')
WHERE status = 'blocked';

ALTER TABLE pipeline_runs DROP CONSTRAINT IF EXISTS chk_pipeline_runs_status;
ALTER TABLE pipeline_runs ADD CONSTRAINT chk_pipeline_runs_status CHECK (
    status IN ('pending', 'running', 'completed', 'partial', 'failed', 'canceled', 'timeout')
);

-- expand-contract-ok: down migration of 001152; drops only the columns it added
ALTER TABLE pipeline_runs DROP COLUMN IF EXISTS refusal_code;
ALTER TABLE scans DROP COLUMN IF EXISTS blocked_runs;
