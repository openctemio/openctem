DROP INDEX IF EXISTS idx_ci_runs_decoration_pending;
ALTER TABLE ci_runs DROP COLUMN IF EXISTS decoration_updated_at;
ALTER TABLE ci_runs DROP COLUMN IF EXISTS decoration_detail;
ALTER TABLE ci_runs DROP COLUMN IF EXISTS decoration_attempts;
ALTER TABLE ci_runs DROP COLUMN IF EXISTS decoration_state;
