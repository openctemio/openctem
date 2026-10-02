-- =============================================================================
-- Migration 018: Pipelines (Down)
-- =============================================================================

-- Drop FK constraint on commands first
ALTER TABLE commands DROP CONSTRAINT IF EXISTS commands_step_run_id_fkey;

DROP TRIGGER IF EXISTS trigger_pipeline_templates_updated_at ON pipeline_templates;

DROP TABLE IF EXISTS step_runs;
DROP TABLE IF EXISTS pipeline_runs;
DROP TABLE IF EXISTS pipeline_steps;
DROP TABLE IF EXISTS pipeline_templates;

