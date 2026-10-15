-- Back to the index over every open aggregate run. Each pipeline run has at most one row under the
-- pipeline-run key, so the rebuild fails only if an old open run and a new one share an attempt key.
DROP INDEX IF EXISTS idx_ci_runs_aggregate_open;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ci_runs_aggregate_open
    ON ci_runs (tenant_id, pipeline_id, external_run_id, run_attempt, commit_sha)
    WHERE aggregate AND status = 'running';
