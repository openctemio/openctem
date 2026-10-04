-- Reverts 000372: direct user ownership grants access again (000340
-- definitions) and the explicit grants table is removed. Access rows that
-- came only from a grant made after the upgrade (not from ownership) are
-- removed with it.

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
      AND ao.assignment_source IS DISTINCT FROM 'owner_ref'
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

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
            AND ao.assignment_source IS DISTINCT FROM 'owner_ref'
      );
END;
$$ LANGUAGE plpgsql;

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

-- Access rows backed only by a non-migration grant (made after the upgrade):
-- without the table nothing would explain them.
DELETE FROM user_accessible_assets uaa
USING asset_access_grants aag
WHERE aag.source = 'manual'
  AND uaa.user_id = aag.user_id AND uaa.asset_id = aag.asset_id
  AND NOT EXISTS (
      SELECT 1 FROM group_members gm
      JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
      JOIN asset_owners ao ON ao.group_id = gm.group_id AND ao.asset_id = aag.asset_id
      WHERE gm.user_id = aag.user_id)
  AND NOT EXISTS (
      SELECT 1 FROM asset_owners ao
      WHERE ao.asset_id = aag.asset_id AND ao.user_id = aag.user_id
        AND ao.assignment_source IS DISTINCT FROM 'owner_ref');

DROP FUNCTION IF EXISTS refresh_access_for_grant_add(UUID, UUID);
DROP FUNCTION IF EXISTS refresh_access_for_grant_remove(UUID, UUID);
DROP TABLE IF EXISTS asset_access_grants;
