-- Undo the conversion of legacy campaigns into tasks.
--
-- Destructive: the tasks the conversion created are deleted with everything
-- done on them since (title, owner and deadline edits, members moved in,
-- tracker issues linked to them, their timeline). Their findings go back to
-- being tracked by the campaign's finding_filter, which the up migration left
-- unchanged. Tasks that joined a campaign leave it again (only while they are
-- still in that campaign). The audit rows and notices the up migration wrote
-- are history and stay.

-- Tasks that joined a campaign leave it.
UPDATE remediation_tasks t
   SET campaign_id = NULL, version = t.version + 1, updated_at = now(), recomputed_at = 'epoch'
  FROM remediation_task_events e
 WHERE e.tenant_id = t.tenant_id AND e.task_id = t.id
   AND e.kind = 'updated' AND e.data ->> 'origin' = 'campaign_migration'
   AND t.campaign_id = (e.data ->> 'campaign_id')::uuid;

DELETE FROM remediation_task_events
 WHERE kind IN ('updated', 'campaign_conflict', 'members_added')
   AND data ->> 'origin' = 'campaign_migration';

DELETE FROM finding_activities
 WHERE activity_type = 'remediation_task_changed'
   AND changes ->> 'origin' = 'campaign_migration';

-- The tasks the conversion created (members, events and tracker links cascade),
-- then their actions.
CREATE TEMP TABLE rcm_down AS
SELECT t.tenant_id, t.id, t.action_id
  FROM remediation_tasks t
 WHERE EXISTS (SELECT 1 FROM remediation_task_events e
                WHERE e.tenant_id = t.tenant_id AND e.task_id = t.id
                  AND e.kind = 'created' AND e.data ->> 'origin' = 'campaign_migration');

DELETE FROM remediation_tasks t USING rcm_down d WHERE t.tenant_id = d.tenant_id AND t.id = d.id;

DELETE FROM remediation_actions a
 USING rcm_down d
 WHERE a.tenant_id = d.tenant_id AND a.id = d.action_id
   AND NOT EXISTS (SELECT 1 FROM remediation_tasks t WHERE t.tenant_id = a.tenant_id AND t.action_id = a.id);

DROP TABLE rcm_down;

DROP FUNCTION IF EXISTS remediation_campaigns_to_tasks(boolean);
DROP FUNCTION IF EXISTS remediation_campaign_filter_parse(jsonb);
