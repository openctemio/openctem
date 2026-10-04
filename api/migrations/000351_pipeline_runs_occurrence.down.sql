DROP INDEX IF EXISTS uq_pipeline_runs_scan_occurrence;
ALTER TABLE pipeline_runs DROP COLUMN IF EXISTS scheduled_for;
