DELETE FROM ticket_links WHERE task_id IS NOT NULL;
DROP INDEX IF EXISTS idx_ticket_links_task;
DROP INDEX IF EXISTS ux_ticket_links_task_issue;
ALTER TABLE ticket_links DROP CONSTRAINT IF EXISTS chk_ticket_links_one_object;
ALTER TABLE ticket_links
    ADD CONSTRAINT chk_ticket_links_one_object CHECK ((finding_id IS NULL) <> (campaign_id IS NULL));
ALTER TABLE ticket_links DROP CONSTRAINT IF EXISTS fk_ticket_links_task_tenant;
ALTER TABLE ticket_links DROP COLUMN IF EXISTS last_pushed_state;
ALTER TABLE ticket_links DROP COLUMN IF EXISTS task_id;
