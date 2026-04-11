DROP INDEX IF EXISTS idx_attachments_dedup;
ALTER TABLE attachments DROP COLUMN IF EXISTS content_hash;
