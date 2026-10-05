-- Reverses 001069_ci_pipelines.up.sql. Runs keep everything they had before
-- the up migration; only the pipeline link and the run attributes it added
-- go.

DROP INDEX IF EXISTS idx_ci_runs_tenant_pipeline;
ALTER TABLE ci_runs DROP CONSTRAINT IF EXISTS fk_ci_runs_pipeline;
ALTER TABLE ci_runs DROP CONSTRAINT IF EXISTS chk_ci_runs_tools;
ALTER TABLE ci_runs
    DROP COLUMN IF EXISTS pipeline_id,
    DROP COLUMN IF EXISTS sensor_version,
    DROP COLUMN IF EXISTS scan_failures,
    DROP COLUMN IF EXISTS tools,
    DROP COLUMN IF EXISTS template_ref;

DROP TABLE IF EXISTS ci_pipelines;
