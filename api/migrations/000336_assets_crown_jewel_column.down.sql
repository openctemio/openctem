-- Put the flag back into properties, where the previous release reads it.
-- The column itself predates 000336 (000126) and the previous release's
-- scoping summary reads it, so it is kept, only relaxed back to nullable.
UPDATE assets
   SET properties = COALESCE(properties, '{}'::jsonb) || '{"is_crown_jewel": true}'::jsonb
 WHERE is_crown_jewel;

ALTER TABLE assets ALTER COLUMN is_crown_jewel DROP NOT NULL;

DROP INDEX IF EXISTS idx_assets_crown_jewel;
CREATE INDEX IF NOT EXISTS idx_assets_crown_jewel ON assets (tenant_id, is_crown_jewel) WHERE is_crown_jewel = TRUE;

COMMENT ON COLUMN assets.is_crown_jewel IS NULL;
