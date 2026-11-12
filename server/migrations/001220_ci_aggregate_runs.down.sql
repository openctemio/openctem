DROP TABLE IF EXISTS ci_run_tokens;
DROP INDEX IF EXISTS idx_ci_runs_aggregate_open;
ALTER TABLE ci_runs DROP COLUMN IF EXISTS aggregate;
