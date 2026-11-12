DROP INDEX IF EXISTS idx_scan_runs_parent_run;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS fk_scan_runs_parent_run;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS parent_run_id;
