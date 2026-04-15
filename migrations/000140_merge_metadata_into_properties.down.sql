-- Rollback: re-add metadata column (data cannot be fully restored)
ALTER TABLE assets ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;
CREATE INDEX IF NOT EXISTS idx_assets_metadata ON assets USING GIN (metadata);
