ALTER TABLE assets DROP COLUMN IF EXISTS freshness_status;
DROP INDEX IF EXISTS idx_approval_velocity;
DROP INDEX IF EXISTS idx_assets_stale_check;
