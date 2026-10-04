DROP INDEX IF EXISTS idx_pipeline_runs_open_deadline;
ALTER TABLE pipeline_runs DROP CONSTRAINT IF EXISTS chk_pipeline_runs_unfinished_targets;
ALTER TABLE pipeline_runs DROP COLUMN IF EXISTS unfinished_targets;
ALTER TABLE pipeline_runs DROP COLUMN IF EXISTS deadline_at;
