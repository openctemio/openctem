-- Automations that use a trigger or action the platform does not run are
-- switched off. finding_updated and webhook triggers never fire, and the
-- trigger_pipeline action is refused (an automation runs a saved scan through
-- trigger_scan). The older unsupported types are included so no active
-- automation is left holding one.
--
-- The rows stay readable: GET /workflows/{id} lists the refused types in
-- unsupported_features, which is the reason shown in the console, and the API
-- refuses to switch such an automation back on until the node is replaced.
UPDATE workflows w
SET is_active = false,
    updated_at = now()
WHERE w.is_active
  AND EXISTS (
      SELECT 1
      FROM workflow_nodes n
      WHERE n.workflow_id = w.id
        AND (n.config->>'trigger_type' IN ('finding_updated', 'webhook', 'schedule', 'finding_age')
             OR n.config->>'action_type' IN ('trigger_pipeline', 'assign_team', 'update_priority', 'run_script'))
  );
