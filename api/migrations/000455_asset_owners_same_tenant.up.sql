-- An access group's assets must be assets of the group's own tenant.
--
-- asset_owners has no tenant_id: a group row is tied to a tenant only through
-- its group, and the asset through the asset. Until the insert paths checked
-- the asset, POST /groups/{g}/assets accepted another tenant's asset id, the
-- group's asset list then showed that asset's name, and the access refresh
-- wrote a user_accessible_assets row (tenant of the group, asset of the other
-- tenant). The API now inserts only same-tenant rows and every read joins the
-- asset to the group's tenant; this migration
--
--   1. deletes any cross-tenant group row and access row already written
--      (only rows whose two tenants differ; the counts go to the server log),
--   2. makes the access refresh functions join the asset to the group's
--      tenant, so they never materialize a foreign asset, and
--   3. adds a trigger that refuses a cross-tenant group row from any writer,
--      present or future, as a last line behind the API's own checks.

DO $$
DECLARE
    owners_removed INT;
    access_removed INT;
BEGIN
    DELETE FROM asset_owners ao
    USING groups g, assets a
    WHERE g.id = ao.group_id
      AND a.id = ao.asset_id
      AND a.tenant_id <> g.tenant_id;
    GET DIAGNOSTICS owners_removed = ROW_COUNT;

    DELETE FROM user_accessible_assets uaa
    USING assets a
    WHERE a.id = uaa.asset_id
      AND a.tenant_id <> uaa.tenant_id;
    GET DIAGNOSTICS access_removed = ROW_COUNT;

    RAISE LOG 'asset owners same tenant: % cross-tenant group asset rows and % cross-tenant access rows removed',
        owners_removed, access_removed;
END $$;

-- Asset assigned to a group: its members see the asset, only when the asset
-- is in the group's tenant.
CREATE OR REPLACE FUNCTION refresh_access_for_asset_assign(
    p_group_id UUID,
    p_asset_id UUID,
    p_ownership_type VARCHAR
)
RETURNS void AS $$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT gm.user_id, g.tenant_id, a.id, p_ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN assets a ON a.id = p_asset_id AND a.tenant_id = g.tenant_id
    WHERE gm.group_id = p_group_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- User added to a group: they see the group's assets of the group's tenant.
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
    JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = g.tenant_id
    WHERE ao.group_id = p_group_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- Full refresh: groups (same-tenant assets only) plus explicit grants.
CREATE OR REPLACE FUNCTION refresh_user_accessible_assets()
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = g.tenant_id
    UNION
    SELECT DISTINCT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- A group row must name an asset of the group's tenant.
CREATE OR REPLACE FUNCTION asset_owners_same_tenant_check()
RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM groups g
        JOIN assets a ON a.tenant_id = g.tenant_id
        WHERE g.id = NEW.group_id AND a.id = NEW.asset_id
    ) THEN
        RAISE EXCEPTION 'asset_owners: asset % is not in the tenant of group %', NEW.asset_id, NEW.group_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS asset_owners_same_tenant ON asset_owners;
CREATE TRIGGER asset_owners_same_tenant
    BEFORE INSERT OR UPDATE OF asset_id, group_id ON asset_owners
    FOR EACH ROW
    WHEN (NEW.group_id IS NOT NULL)
    EXECUTE FUNCTION asset_owners_same_tenant_check();
