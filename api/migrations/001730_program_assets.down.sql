DROP TABLE IF EXISTS asset_program_links;
DROP INDEX IF EXISTS idx_assets_system_tags;
DROP INDEX IF EXISTS idx_assets_program_only;
ALTER TABLE assets
    DROP COLUMN IF EXISTS program_only,
    DROP COLUMN IF EXISTS system_tags;
