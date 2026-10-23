-- Removed automation types (research/238 G6). The schedule, finding_age,
-- finding_updated and webhook triggers, the assign_team, update_priority,
-- run_script, http_request and trigger_pipeline actions and the pagerduty
-- notification never ran: nothing fired them, or every run failed or was
-- refused. The API no longer knows them as types.
--
-- No automation is deleted. Every automation that still holds a node of a
-- removed type is switched off and says why in the new disabled_reason
-- column (uses_removed_type); it stays readable, the console names the
-- removed node, and the automation cannot be switched on again until the
-- node is replaced (which clears the reason). Automations that were already
-- off are marked too, so the reason is shown for them as well.
--
-- The stored headers of http_request nodes are removed: they often held
-- credentials in plain node config, the action never runs again, and no
-- reader of the automation was ever shown them.

ALTER TABLE automations
    ADD COLUMN disabled_reason VARCHAR(40),
    ADD CONSTRAINT chk_automations_disabled_reason
        CHECK (disabled_reason IS NULL OR disabled_reason IN ('uses_removed_type'));

COMMENT ON COLUMN automations.disabled_reason IS
    'Why the platform switched the automation off: uses_removed_type = it holds a trigger, action or notification type that no longer exists; NULL = not switched off by the platform';

UPDATE automations a
   SET is_active = false,
       disabled_reason = 'uses_removed_type',
       updated_at = now()
 WHERE EXISTS (
       SELECT 1
         FROM automation_nodes n
        WHERE n.automation_id = a.id
          AND (n.config->>'trigger_type' IN ('schedule', 'finding_age', 'finding_updated', 'webhook')
               OR n.config->>'action_type' IN ('assign_team', 'update_priority', 'run_script', 'http_request', 'trigger_pipeline')
               OR n.config->>'notification_type' = 'pagerduty'));

UPDATE automation_nodes
   SET config = config #- '{action_config,headers}'
 WHERE config->>'action_type' = 'http_request'
   AND config->'action_config' ? 'headers';
