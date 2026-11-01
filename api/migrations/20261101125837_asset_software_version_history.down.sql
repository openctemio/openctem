DROP INDEX IF EXISTS idx_asset_software_established;
-- A candidate becomes a plain current link again: the previous code
-- supersedes the older version on its next sighting.
ALTER TABLE asset_software
    DROP CONSTRAINT IF EXISTS chk_asset_software_streak,
    DROP CONSTRAINT IF EXISTS chk_asset_software_sightings,
    DROP CONSTRAINT IF EXISTS chk_asset_software_evidence_class,
    DROP CONSTRAINT IF EXISTS chk_asset_software_version_state,
    DROP COLUMN IF EXISTS streak_since,
    DROP COLUMN IF EXISTS streak,
    DROP COLUMN IF EXISTS sightings,
    DROP COLUMN IF EXISTS evidence_class,
    DROP COLUMN IF EXISTS version_state;
COMMENT ON COLUMN asset_software.superseded_at IS NULL;
