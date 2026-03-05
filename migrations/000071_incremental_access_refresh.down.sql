-- Drop incremental functions
DROP FUNCTION IF EXISTS refresh_access_for_asset_assign(UUID, UUID, VARCHAR);
DROP FUNCTION IF EXISTS refresh_access_for_asset_unassign(UUID, UUID);
DROP FUNCTION IF EXISTS refresh_access_for_member_add(UUID, UUID);
DROP FUNCTION IF EXISTS refresh_access_for_member_remove(UUID, UUID);

-- Remove unique constraint
ALTER TABLE user_accessible_assets DROP CONSTRAINT IF EXISTS uq_user_accessible_assets;

-- Restore original full-refresh function (with original bug for exact rollback)
CREATE OR REPLACE FUNCTION refresh_user_accessible_assets()
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    WHERE gm.is_active = TRUE;
END;
$$ LANGUAGE plpgsql;
