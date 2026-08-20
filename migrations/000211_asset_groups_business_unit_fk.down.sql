-- =============================================================================
-- Migration 211: asset_groups.business_unit FK (Down)
-- =============================================================================
-- Drops the reconciled FK column and its index. The free-text business_unit
-- column is left intact, so no group data is lost on rollback.

DROP INDEX IF EXISTS idx_asset_groups_business_unit_id;

ALTER TABLE asset_groups
    DROP COLUMN IF EXISTS business_unit_id;
