ALTER TABLE assets
    DROP COLUMN IF EXISTS is_crown_jewel,
    DROP COLUMN IF EXISTS business_impact_score,
    DROP COLUMN IF EXISTS business_impact_notes;

DROP INDEX IF EXISTS idx_assets_crown_jewel;
DROP TABLE IF EXISTS business_unit_assets;
DROP TABLE IF EXISTS business_units;
