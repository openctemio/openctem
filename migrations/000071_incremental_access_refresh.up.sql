-- =============================================================================
-- Migration 000071: Incremental Access Refresh
-- =============================================================================
-- Replaces DELETE ALL + INSERT ALL with targeted incremental functions.
-- Also fixes bug: original refresh_user_accessible_assets() referenced
-- gm.is_active which doesn't exist on group_members table.
-- =============================================================================

-- Deduplicate existing rows (required before adding unique constraint)
DELETE FROM user_accessible_assets a USING user_accessible_assets b
WHERE a.ctid < b.ctid
  AND a.user_id = b.user_id
  AND a.tenant_id = b.tenant_id
  AND a.asset_id = b.asset_id;

-- Add unique constraint for ON CONFLICT support
DO $$ BEGIN
    ALTER TABLE user_accessible_assets
    ADD CONSTRAINT uq_user_accessible_assets UNIQUE (user_id, tenant_id, asset_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- =============================================================================
-- 1. refresh_access_for_asset_assign
-- Called when an asset is assigned to a group.
-- Inserts access rows for all members of that group.
-- =============================================================================
CREATE OR REPLACE FUNCTION refresh_access_for_asset_assign(
    p_group_id UUID,
    p_asset_id UUID,
    p_ownership_type VARCHAR
)
RETURNS void AS $$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT gm.user_id, g.tenant_id, p_asset_id, p_ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    WHERE gm.group_id = p_group_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 2. refresh_access_for_asset_unassign
-- Called when an asset is removed from a group.
-- Removes access rows only if user has no other group granting access to this asset.
-- =============================================================================
CREATE OR REPLACE FUNCTION refresh_access_for_asset_unassign(
    p_group_id UUID,
    p_asset_id UUID
)
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets uaa
    WHERE uaa.asset_id = p_asset_id
      AND uaa.user_id IN (
          SELECT gm.user_id FROM group_members gm WHERE gm.group_id = p_group_id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM group_members gm2
          JOIN groups g2 ON g2.id = gm2.group_id AND g2.is_active = TRUE
          JOIN asset_owners ao2 ON ao2.group_id = gm2.group_id AND ao2.asset_id = p_asset_id
          WHERE gm2.user_id = uaa.user_id
            AND gm2.group_id != p_group_id
      );
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 3. refresh_access_for_member_add
-- Called when a user is added to a group.
-- Inserts access rows for all assets owned by that group.
-- =============================================================================
CREATE OR REPLACE FUNCTION refresh_access_for_member_add(
    p_group_id UUID,
    p_user_id UUID
)
RETURNS void AS $$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT p_user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM asset_owners ao
    JOIN groups g ON g.id = ao.group_id AND g.is_active = TRUE
    WHERE ao.group_id = p_group_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 4. refresh_access_for_member_remove
-- Called when a user is removed from a group.
-- Removes access rows only if user has no other group granting access to those assets.
-- =============================================================================
CREATE OR REPLACE FUNCTION refresh_access_for_member_remove(
    p_group_id UUID,
    p_user_id UUID
)
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets uaa
    WHERE uaa.user_id = p_user_id
      AND uaa.asset_id IN (
          SELECT ao.asset_id FROM asset_owners ao WHERE ao.group_id = p_group_id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM group_members gm2
          JOIN groups g2 ON g2.id = gm2.group_id AND g2.is_active = TRUE
          JOIN asset_owners ao2 ON ao2.group_id = gm2.group_id AND ao2.asset_id = uaa.asset_id
          WHERE gm2.user_id = p_user_id
            AND gm2.group_id != p_group_id
      );
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Fix: Replace the original full-refresh function (removes gm.is_active bug)
-- =============================================================================
CREATE OR REPLACE FUNCTION refresh_user_accessible_assets()
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;
