ALTER TABLE asset_technologies
    DROP CONSTRAINT IF EXISTS chk_asset_technologies_cpe,
    DROP CONSTRAINT IF EXISTS chk_asset_technologies_vendor,
    DROP COLUMN IF EXISTS cpe,
    DROP COLUMN IF EXISTS vendor;
