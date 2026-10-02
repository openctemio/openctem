-- =============================================================================
-- Migration 083: Asset Ownership Wiring
-- OpenCTEM OSS Edition
-- =============================================================================
-- 1. Add 'regulatory' to ownership_type CHECK constraint
-- 2. Fix refresh_user_accessible_assets to include direct user ownership
-- 3. Add incremental refresh functions for direct owner add/remove
-- =============================================================================

-- 1. Add 'regulatory' to ownership_type CHECK constraint
ALTER TABLE asset_owners DROP CONSTRAINT IF EXISTS chk_ownership_type;
ALTER TABLE asset_owners ADD CONSTRAINT chk_ownership_type
    CHECK (ownership_type IN ('primary', 'secondary', 'stakeholder', 'informed', 'regulatory'));

-- 2. Fix refresh_user_accessible_assets to include direct user ownership (Path B)
CREATE OR REPLACE FUNCTION refresh_user_accessible_assets()
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    -- Path A: group-based access (existing)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    UNION
    -- Path B: direct user-based access (NEW)
    SELECT DISTINCT ao.user_id, a.tenant_id, ao.asset_id, ao.ownership_type
    FROM asset_owners ao
    JOIN assets a ON a.id = ao.asset_id
    WHERE ao.user_id IS NOT NULL
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- 3. Incremental refresh: direct owner add
CREATE OR REPLACE FUNCTION refresh_access_for_direct_owner_add(
    p_asset_id UUID, p_user_id UUID, p_ownership_type VARCHAR
) RETURNS void AS $$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT p_user_id, a.tenant_id, a.id, p_ownership_type
    FROM assets a WHERE a.id = p_asset_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- 4. Incremental refresh: direct owner remove
CREATE OR REPLACE FUNCTION refresh_access_for_direct_owner_remove(
    p_asset_id UUID, p_user_id UUID
) RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets uaa
    WHERE uaa.user_id = p_user_id AND uaa.asset_id = p_asset_id
      -- Only remove if no other path grants access
      AND NOT EXISTS (
          SELECT 1 FROM group_members gm
          JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
          JOIN asset_owners ao ON ao.group_id = gm.group_id AND ao.asset_id = p_asset_id
          WHERE gm.user_id = p_user_id
      )
      AND NOT EXISTS (
          SELECT 1 FROM asset_owners ao
          WHERE ao.asset_id = p_asset_id AND ao.user_id = p_user_id
      );
END;
$$ LANGUAGE plpgsql;

-- 5. Refresh existing data to include direct user owners
SELECT refresh_user_accessible_assets();
