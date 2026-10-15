DROP INDEX IF EXISTS idx_ci_runs_pipeline_run;
ALTER TABLE ci_runs
    DROP COLUMN IF EXISTS carried_scan_failures,
    DROP COLUMN IF EXISTS evidence_union;
