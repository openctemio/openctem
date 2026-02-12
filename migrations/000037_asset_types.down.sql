-- Remove FK constraint from assets
ALTER TABLE assets DROP CONSTRAINT IF EXISTS fk_assets_asset_type;

-- Drop triggers
DROP TRIGGER IF EXISTS update_asset_types_updated_at ON asset_types;
DROP TRIGGER IF EXISTS update_asset_type_categories_updated_at ON asset_type_categories;

-- Drop tables
DROP TABLE IF EXISTS asset_types;
DROP TABLE IF EXISTS asset_type_categories;
