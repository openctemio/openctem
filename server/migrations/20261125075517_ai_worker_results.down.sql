DROP TABLE IF EXISTS ai_auto_change_counts;
ALTER TABLE tenant_ai_settings DROP COLUMN IF EXISTS autonomy;
ALTER TABLE ai_runs DROP CONSTRAINT IF EXISTS chk_ai_runs_model_family;
ALTER TABLE ai_runs DROP CONSTRAINT IF EXISTS chk_ai_runs_action_log;
ALTER TABLE ai_runs DROP CONSTRAINT IF EXISTS chk_ai_runs_outcome;
ALTER TABLE ai_runs
    DROP COLUMN IF EXISTS model_family,
    DROP COLUMN IF EXISTS action_log,
    DROP COLUMN IF EXISTS outcome,
    DROP COLUMN IF EXISTS subject_row_version;
