DROP INDEX IF EXISTS idx_assets_owner_ref;
ALTER TABLE assets DROP COLUMN IF EXISTS owner_ref;
