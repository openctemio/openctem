ALTER TABLE scan_run_steps
    DROP COLUMN IF EXISTS findings_held,
    DROP COLUMN IF EXISTS findings_refused;
