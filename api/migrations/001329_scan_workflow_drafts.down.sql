ALTER TABLE scan_workflows
    DROP COLUMN IF EXISTS draft_updated_at,
    DROP COLUMN IF EXISTS draft_issues,
    DROP COLUMN IF EXISTS draft;
