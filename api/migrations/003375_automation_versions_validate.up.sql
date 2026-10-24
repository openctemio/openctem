-- Validates the mode checks added NOT VALID by automation_versions, as their
-- own step: SHARE UPDATE EXCLUSIVE, writes keep flowing.
ALTER TABLE automations VALIDATE CONSTRAINT chk_automations_mode;
ALTER TABLE automation_runs VALIDATE CONSTRAINT chk_automation_runs_mode;
