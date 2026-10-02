-- Add content_hash for file deduplication within a finding.
-- SHA-256 hash of file content, checked before upload to prevent duplicates.
ALTER TABLE attachments ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64);

-- Index for dedup lookup: same hash + same context = duplicate
CREATE INDEX IF NOT EXISTS idx_attachments_dedup
    ON attachments(tenant_id, context_type, context_id, content_hash)
    WHERE content_hash IS NOT NULL;
