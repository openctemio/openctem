-- Removes AI analysts. The service accounts behind them stay (they are plain
-- service accounts again); delete them from Settings if they are not wanted.
DROP INDEX IF EXISTS idx_finding_activities_ai_run;
DROP TRIGGER IF EXISTS trigger_label_ai_analyst_activity ON finding_activities;
DROP FUNCTION IF EXISTS label_ai_analyst_activity();
DROP TABLE IF EXISTS ai_runs;
DROP TABLE IF EXISTS ai_analyst_owners;
DROP FUNCTION IF EXISTS refuse_foreign_ai_analyst_owner();
DROP TABLE IF EXISTS ai_analysts;
DROP FUNCTION IF EXISTS refuse_ai_analyst_non_service();
