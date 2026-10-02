-- Revert asset type module mapping
ALTER TABLE asset_types DROP CONSTRAINT IF EXISTS fk_asset_types_module;
DROP INDEX IF EXISTS idx_asset_types_module_id;
ALTER TABLE asset_types DROP COLUMN IF EXISTS module_id;
