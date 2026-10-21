-- The task owner's access to the findings of the tasks they own is decided
-- per read (the owner is the task's user, or a team they are an active
-- member of, and the task is live): two small partial indexes make that
-- lookup an index probe instead of a scan of the tenant's tasks.
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_live_owner_user
    ON remediation_tasks (tenant_id, assignee_user_id)
    WHERE assignee_user_id IS NOT NULL AND state IN ('open', 'in_progress', 'verifying', 'on_hold');
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_live_owner_group
    ON remediation_tasks (tenant_id, assignee_group_id)
    WHERE assignee_group_id IS NOT NULL AND state IN ('open', 'in_progress', 'verifying', 'on_hold');
