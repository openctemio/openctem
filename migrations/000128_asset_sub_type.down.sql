-- Rollback: just drop the column. No data changes needed since Phase 1
-- did not modify asset_type values.
DROP INDEX IF EXISTS idx_assets_sub_type;
ALTER TABLE assets DROP COLUMN IF EXISTS sub_type;
