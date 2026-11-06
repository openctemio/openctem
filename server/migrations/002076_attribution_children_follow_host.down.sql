DROP INDEX IF EXISTS idx_asset_attributions_follows_host;
ALTER TABLE asset_attributions DROP CONSTRAINT IF EXISTS chk_asset_attributions_follows_other;
ALTER TABLE asset_attributions DROP CONSTRAINT IF EXISTS fk_asset_attributions_follows_host;
ALTER TABLE asset_attributions DROP COLUMN IF EXISTS follows_host_id;
