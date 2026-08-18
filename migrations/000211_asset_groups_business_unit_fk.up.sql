-- =============================================================================
-- Migration 211: asset_groups.business_unit — free-text → business_units FK
-- =============================================================================
-- asset_groups.business_unit is a legacy free-text string (migration 000024)
-- that was never reconciled with the first-class business_units entity
-- (migration 000126). This adds a nullable FK alongside the string so a group
-- can point at the real BU record, without removing the free-text column.
--
-- Additive + back-compat:
--   - business_unit_id is nullable; free-text values that don't match any BU
--     stay NULL and the string keeps working exactly as before.
--   - The old string column and its index are untouched.
--   - ON DELETE SET NULL: deleting a BU doesn't cascade-delete groups, it just
--     clears the reconciled link (the string label remains for reference).
--
-- Backfill matches per-tenant by case-insensitive name — business_units has a
-- UNIQUE(tenant_id, name) constraint, so the match is unambiguous.

ALTER TABLE asset_groups
    ADD COLUMN IF NOT EXISTS business_unit_id UUID
    REFERENCES business_units(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_asset_groups_business_unit_id
    ON asset_groups(business_unit_id);

-- Backfill existing rows by case-insensitive per-tenant name match.
UPDATE asset_groups ag
SET business_unit_id = bu.id
FROM business_units bu
WHERE bu.tenant_id = ag.tenant_id
  AND ag.business_unit IS NOT NULL
  AND ag.business_unit <> ''
  AND lower(bu.name) = lower(ag.business_unit)
  AND ag.business_unit_id IS NULL;
