-- Rollback Migration 000207: CTEM Scoping critical-asset register attributes

DROP INDEX IF EXISTS idx_asset_rel_control_plane;

ALTER TABLE asset_relationships
    DROP COLUMN IF EXISTS is_control_plane;

ALTER TABLE assets
    DROP CONSTRAINT IF EXISTS chk_assets_impact_confidentiality,
    DROP CONSTRAINT IF EXISTS chk_assets_impact_integrity,
    DROP CONSTRAINT IF EXISTS chk_assets_impact_availability;

ALTER TABLE assets
    DROP COLUMN IF EXISTS impact_confidentiality,
    DROP COLUMN IF EXISTS impact_integrity,
    DROP COLUMN IF EXISTS impact_availability;
