DROP FUNCTION IF EXISTS public.refresh_user_accessible_assets_for_tenant(uuid);

CREATE OR REPLACE FUNCTION public.refresh_access_for_asset_assign(p_group_id uuid, p_asset_id uuid, p_ownership_type character varying)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT gm.user_id, g.tenant_id, a.id, p_ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN assets a ON a.id = p_asset_id AND a.tenant_id = g.tenant_id
    WHERE gm.group_id = p_group_id
      AND principal_is_active(g.tenant_id, gm.user_id)
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$function$;

CREATE OR REPLACE FUNCTION public.refresh_access_for_member_add(p_group_id uuid, p_user_id uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT p_user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM asset_owners ao
    JOIN groups g ON g.id = ao.group_id AND g.is_active = TRUE
    JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = g.tenant_id
    WHERE ao.group_id = p_group_id
      AND principal_is_active(g.tenant_id, p_user_id)
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$function$;

CREATE OR REPLACE FUNCTION public.refresh_access_for_user(p_tenant_id uuid, p_user_id uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    DELETE FROM user_accessible_assets
    WHERE tenant_id = p_tenant_id AND user_id = p_user_id;

    IF NOT principal_is_active(p_tenant_id, p_user_id) THEN
        RETURN;
    END IF;

    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE AND g.tenant_id = p_tenant_id
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = g.tenant_id
    WHERE gm.user_id = p_user_id
    UNION
    SELECT DISTINCT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    WHERE aag.tenant_id = p_tenant_id AND aag.user_id = p_user_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$function$;

CREATE OR REPLACE FUNCTION public.refresh_user_accessible_assets()
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    DELETE FROM user_accessible_assets;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = g.tenant_id
    WHERE principal_is_active(g.tenant_id, gm.user_id)
    UNION
    SELECT DISTINCT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    WHERE principal_is_active(aag.tenant_id, aag.user_id)
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$function$;
