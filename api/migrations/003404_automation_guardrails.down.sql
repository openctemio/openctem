-- Paused runs end as failed (the old engine has no paused state); the
-- automations switched off stay off.
UPDATE automation_runs SET status = 'failed', error_message = 'paused at the change cap', completed_at = now()
 WHERE status = 'paused';
ALTER TABLE automation_runs DROP CONSTRAINT IF EXISTS chk_automation_runs_pause_reason;
ALTER TABLE automation_runs DROP COLUMN IF EXISTS pause_reason;
ALTER TABLE automation_runs DROP CONSTRAINT chk_run_status;
ALTER TABLE automation_runs ADD CONSTRAINT chk_run_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'canceled'));

UPDATE automations SET disabled_reason = NULL WHERE disabled_reason = 'status_not_allowed';
ALTER TABLE automations DROP CONSTRAINT chk_automations_disabled_reason;
ALTER TABLE automations ADD CONSTRAINT chk_automations_disabled_reason
    CHECK (disabled_reason IS NULL OR disabled_reason IN ('uses_removed_type'));
ALTER TABLE automations DROP CONSTRAINT IF EXISTS chk_automations_max_changes;
ALTER TABLE automations DROP COLUMN IF EXISTS max_changes_per_run;
