-- Migration 000140: Merge metadata into properties, drop metadata column
--
-- The assets table has both `properties` (scanner data) and `metadata` (user data).
-- UI already merges both: metadata = { ...properties, ...metadata }
-- Simplify: one column `properties` for everything.

-- Step 1: Merge metadata into properties (metadata wins on conflict)
UPDATE assets
SET properties = COALESCE(properties, '{}'::jsonb) || COALESCE(metadata, '{}'::jsonb),
    updated_at = NOW()
WHERE metadata IS NOT NULL AND metadata != '{}'::jsonb;

-- Step 2: Drop metadata GIN index
DROP INDEX IF EXISTS idx_assets_metadata;

-- Step 3: Drop metadata column
ALTER TABLE assets DROP COLUMN IF EXISTS metadata;
