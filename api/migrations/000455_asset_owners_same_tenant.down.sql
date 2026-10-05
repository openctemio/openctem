-- The removed cross-tenant rows were invalid; they are not restored. The
-- refresh functions go back to their 000071 / 000372 definitions.

DROP TRIGGER IF EXISTS asset_owners_same_tenant ON asset_owners;
DROP FUNCTION IF EXISTS asset_owners_same_tenant_check();

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
    SELECT DISTINCT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;
