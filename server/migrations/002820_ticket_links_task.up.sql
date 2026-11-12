-- Ticket links of remediation tasks (research 157 P1, one issue per task by
-- default): a link names exactly one of a finding, a campaign or a task, and
-- records the task state last pushed to the issue so a missed push is
-- retried by the reconciler.
--
-- Live impact: ticket_links is small (0 rows live at the time of writing);
-- the new foreign key and check are added NOT VALID and validated in the next
-- migration.
ALTER TABLE ticket_links ADD COLUMN IF NOT EXISTS task_id uuid;
ALTER TABLE ticket_links ADD COLUMN IF NOT EXISTS last_pushed_state varchar(32) NOT NULL DEFAULT '';

ALTER TABLE ticket_links DROP CONSTRAINT IF EXISTS fk_ticket_links_task_tenant;
ALTER TABLE ticket_links
    ADD CONSTRAINT fk_ticket_links_task_tenant FOREIGN KEY (tenant_id, task_id)
    REFERENCES remediation_tasks (tenant_id, id) ON DELETE CASCADE NOT VALID;

ALTER TABLE ticket_links DROP CONSTRAINT IF EXISTS chk_ticket_links_one_object;
ALTER TABLE ticket_links
    ADD CONSTRAINT chk_ticket_links_one_object CHECK (num_nonnulls(finding_id, campaign_id, task_id) = 1) NOT VALID;

-- One active link per task and issue.
CREATE UNIQUE INDEX IF NOT EXISTS ux_ticket_links_task_issue
    ON ticket_links (tenant_id, task_id, integration_id, external_key)
    WHERE task_id IS NOT NULL AND state = 'active';
CREATE INDEX IF NOT EXISTS idx_ticket_links_task
    ON ticket_links (task_id, tenant_id) WHERE task_id IS NOT NULL;
