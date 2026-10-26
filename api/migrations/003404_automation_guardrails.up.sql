-- Automation guardrails (RFC-125 D9, D14).
--
-- update_status may set only confirmed or in_progress: closing risk (false
-- positive, accepted, resolved, duplicate) is a person's decision, which an
-- automation may only request. An automation whose draft or published version
-- sets another status is switched off and back to simulate, with
-- disabled_reason = status_not_allowed; nothing is deleted, and it can be
-- switched on again once the step is changed and published.
--
-- A live run makes at most max_changes_per_run changes (0: the default, 250;
-- at most 1,000); the next one pauses the run (status paused, pause_reason
-- blast_radius) until a publisher lets it continue.

ALTER TABLE automations
    ADD COLUMN max_changes_per_run INTEGER NOT NULL DEFAULT 0,
    ADD CONSTRAINT chk_automations_max_changes CHECK (max_changes_per_run BETWEEN 0 AND 1000);
COMMENT ON COLUMN automations.max_changes_per_run IS 'Changes one live run may make before it pauses; 0 = the default (250)';

ALTER TABLE automations DROP CONSTRAINT chk_automations_disabled_reason;
ALTER TABLE automations ADD CONSTRAINT chk_automations_disabled_reason
    CHECK (disabled_reason IS NULL OR disabled_reason IN ('uses_removed_type', 'status_not_allowed'));

ALTER TABLE automation_runs DROP CONSTRAINT chk_run_status;
ALTER TABLE automation_runs ADD CONSTRAINT chk_run_status
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'canceled', 'paused'));
ALTER TABLE automation_runs
    ADD COLUMN pause_reason VARCHAR(40),
    ADD CONSTRAINT chk_automation_runs_pause_reason CHECK (pause_reason IS NULL OR pause_reason IN ('blast_radius'));

UPDATE automations a
   SET is_active = false,
       mode = 'simulate',
       disabled_reason = 'status_not_allowed',
       updated_at = now()
 WHERE EXISTS (
           SELECT 1 FROM automation_nodes n
            WHERE n.automation_id = a.id
              AND n.config->>'action_type' = 'update_status'
              AND COALESCE(n.config->'action_config'->>'status', '') NOT IN ('', 'confirmed', 'in_progress'))
    OR EXISTS (
           SELECT 1 FROM automation_versions v, jsonb_array_elements(v.definition->'nodes') node
            WHERE v.id = a.published_version_id
              AND node->'config'->>'action_type' = 'update_status'
              AND COALESCE(node->'config'->'action_config'->>'status', '') NOT IN ('', 'confirmed', 'in_progress'));
