DROP TABLE IF EXISTS remediation_task_events;
DROP TABLE IF EXISTS remediation_task_members;
DROP TABLE IF EXISTS remediation_tasks;
DROP TABLE IF EXISTS remediation_actions;
ALTER TABLE remediation_campaigns DROP CONSTRAINT IF EXISTS uq_remediation_campaigns_tenant_id_id;
