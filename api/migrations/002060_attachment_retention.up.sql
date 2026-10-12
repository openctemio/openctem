-- Attachment retention (RFC-084): evidence whose finding or campaign was
-- deleted is marked orphaned_at when the retention sweep first sees its
-- parent gone, and purged (file and row) once the grace period has passed
-- since then. Uploads never linked to anything are purged by created_at.
-- Additive: a nullable column and two partial indexes on a small table.

ALTER TABLE attachments ADD COLUMN IF NOT EXISTS orphaned_at TIMESTAMPTZ;

COMMENT ON COLUMN attachments.orphaned_at IS
    'When the retention sweep found the finding or campaign this attachment belongs to deleted; purged after the grace period (STORAGE_ORPHAN_GRACE_DAYS)';

CREATE INDEX IF NOT EXISTS idx_attachments_orphaned
    ON attachments (orphaned_at) WHERE orphaned_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_attachments_unlinked
    ON attachments (created_at) WHERE context_id = '';
