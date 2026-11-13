ALTER TABLE ticket_links DROP CONSTRAINT IF EXISTS chk_ticket_links_status_category;
ALTER TABLE ticket_links
    DROP COLUMN IF EXISTS external_updated_at,
    DROP COLUMN IF EXISTS external_status_category,
    DROP COLUMN IF EXISTS external_assignee_name,
    DROP COLUMN IF EXISTS external_assignee_id;
