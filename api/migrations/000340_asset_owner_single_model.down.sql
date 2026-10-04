-- Reverts 000340. Run after 000342's down, which has already copied the
-- 'owner_ref' rows back into assets.owner_id.

-- Restore the 000083 definitions (Path B counts every direct user owner).
CREATE OR REPLACE FUNCTION refresh_user_accessible_assets()
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    UNION
    SELECT DISTINCT ao.user_id, a.tenant_id, ao.asset_id, ao.ownership_type
    FROM asset_owners ao
    JOIN assets a ON a.id = ao.asset_id
    WHERE ao.user_id IS NOT NULL
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION refresh_access_for_direct_owner_remove(
    p_asset_id UUID, p_user_id UUID
) RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets uaa
    WHERE uaa.user_id = p_user_id AND uaa.asset_id = p_asset_id
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

COMMENT ON COLUMN asset_owners.assignment_source IS NULL;

-- Rows derived from owner_ref did not exist before 000340. With the old
-- refresh restored they would grant data access, so remove them.
DELETE FROM asset_owners WHERE assignment_source = 'owner_ref';
