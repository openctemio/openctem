-- External participant on a ticket link (research 220 §5.2): the tracker's
-- assignee of the linked issue (Jira accountId and display name), its status
-- category and when the tracker last changed it, read from inbound webhooks.
-- A label only: never a platform assignee, never a member, no data access.
--
-- Live impact: ADD COLUMN with a constant default (or NULL) only changes the
-- catalog (no table rewrite); the brief ACCESS EXCLUSIVE lock is the same as
-- any ADD COLUMN. Existing links read as unassigned with no category.

ALTER TABLE ticket_links
    ADD COLUMN IF NOT EXISTS external_assignee_id     varchar(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS external_assignee_name   varchar(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS external_status_category varchar(16)  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS external_updated_at      timestamptz;

ALTER TABLE ticket_links DROP CONSTRAINT IF EXISTS chk_ticket_links_status_category;
ALTER TABLE ticket_links ADD CONSTRAINT chk_ticket_links_status_category
    CHECK (external_status_category IN ('', 'todo', 'in_progress', 'done'));

COMMENT ON COLUMN ticket_links.external_assignee_id IS
    'Tracker account of the issue assignee (Jira accountId); empty = unassigned. A label, never a platform user.';
COMMENT ON COLUMN ticket_links.external_assignee_name IS
    'Display name of the tracker assignee as last seen (personal data; removed with the link or the tenant).';
COMMENT ON COLUMN ticket_links.external_status_category IS
    'Tracker status category of the issue: todo, in_progress or done; empty = not seen yet.';
COMMENT ON COLUMN ticket_links.external_updated_at IS
    'When the tracker reported the last change read from it.';
