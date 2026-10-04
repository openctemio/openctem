-- RFC-046 P1.2 (D5): a run or a step that kept some results and lost
-- others ends `partial` instead of `failed`. A zone-routed scan with one
-- failed batch out of twenty, or a pipeline whose second step failed after
-- the first completed, used to end "failed" and read as if nothing had been
-- scanned. `partial` is terminal, keeps its results and is never retried as
-- a whole. The scan counts it separately so the success rate stops treating
-- it as either outcome.

ALTER TABLE pipeline_runs DROP CONSTRAINT IF EXISTS chk_pipeline_runs_status;
ALTER TABLE pipeline_runs ADD CONSTRAINT chk_pipeline_runs_status
    CHECK (status IN ('pending', 'running', 'completed', 'partial', 'failed', 'canceled', 'timeout'));

ALTER TABLE step_runs DROP CONSTRAINT IF EXISTS chk_step_runs_status;
ALTER TABLE step_runs ADD CONSTRAINT chk_step_runs_status
    CHECK (status IN ('pending', 'queued', 'running', 'completed', 'partial', 'failed', 'skipped', 'canceled', 'timeout'));

ALTER TABLE scans ADD COLUMN IF NOT EXISTS partial_runs INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_partial_runs;
ALTER TABLE scans ADD CONSTRAINT chk_scans_partial_runs CHECK (partial_runs >= 0);
