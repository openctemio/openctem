DROP INDEX IF EXISTS idx_attachments_unlinked;
DROP INDEX IF EXISTS idx_attachments_orphaned;
ALTER TABLE attachments DROP COLUMN IF EXISTS orphaned_at;
