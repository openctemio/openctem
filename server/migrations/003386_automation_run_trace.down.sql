DROP INDEX IF EXISTS idx_automation_runs_mode_created;
DROP TABLE IF EXISTS automation_deliveries;
ALTER TABLE automation_run_steps
    DROP COLUMN IF EXISTS skipped,
    DROP COLUMN IF EXISTS out_count,
    DROP COLUMN IF EXISTS in_count;
