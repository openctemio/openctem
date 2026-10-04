-- A partial run kept results but also lost some: the closest older status
-- is failed, which is what it was recorded as before 000350.
UPDATE pipeline_runs SET status = 'failed' WHERE status = 'partial';
UPDATE step_runs SET status = 'failed' WHERE status = 'partial';
UPDATE scans
SET failed_runs = failed_runs + partial_runs,
    last_run_status = CASE WHEN last_run_status = 'partial' THEN 'failed' ELSE last_run_status END
WHERE partial_runs > 0 OR last_run_status = 'partial';

ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_partial_runs;
ALTER TABLE scans DROP COLUMN IF EXISTS partial_runs;

ALTER TABLE step_runs DROP CONSTRAINT IF EXISTS chk_step_runs_status;
ALTER TABLE step_runs ADD CONSTRAINT chk_step_runs_status
    CHECK (status IN ('pending', 'queued', 'running', 'completed', 'failed', 'skipped', 'canceled', 'timeout'));

ALTER TABLE pipeline_runs DROP CONSTRAINT IF EXISTS chk_pipeline_runs_status;
ALTER TABLE pipeline_runs ADD CONSTRAINT chk_pipeline_runs_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'canceled', 'timeout'));
