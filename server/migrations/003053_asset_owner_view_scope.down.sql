-- Restores the scope functions without ownership (002903 / baseline).

DROP TRIGGER IF EXISTS asset_owners_scope_sync ON public.asset_owners;

CREATE OR REPLACE FUNCTION public.trg_asset_owners_scope_sync() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.group_id IS NOT NULL THEN
            PERFORM refresh_access_for_asset_assign(NEW.group_id, NEW.asset_id, NEW.ownership_type);
        END IF;
        RETURN NEW;
    END IF;
    -- DELETE
    IF OLD.group_id IS NOT NULL THEN
        PERFORM refresh_access_for_asset_unassign(OLD.group_id, OLD.asset_id);
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER asset_owners_scope_sync AFTER INSERT OR DELETE ON public.asset_owners FOR EACH ROW EXECUTE FUNCTION public.trg_asset_owners_scope_sync();

CREATE OR REPLACE FUNCTION public.refresh_access_for_asset_unassign(p_group_id uuid, p_asset_id uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
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
      )
      AND NOT EXISTS (
          SELECT 1 FROM asset_access_grants aag
          WHERE aag.asset_id = p_asset_id AND aag.user_id = uaa.user_id
      );
END;
$$;

CREATE OR REPLACE FUNCTION public.refresh_access_for_grant_remove(p_asset_id uuid, p_user_id uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM user_accessible_assets uaa
    WHERE uaa.user_id = p_user_id AND uaa.asset_id = p_asset_id
      AND NOT EXISTS (
          SELECT 1 FROM group_members gm
          JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
          JOIN asset_owners ao ON ao.group_id = gm.group_id AND ao.asset_id = p_asset_id
          WHERE gm.user_id = p_user_id)
      AND NOT EXISTS (
          SELECT 1 FROM asset_access_grants aag
          WHERE aag.asset_id = p_asset_id AND aag.user_id = p_user_id);
END;
$$;

CREATE OR REPLACE FUNCTION public.refresh_access_for_member_remove(p_group_id uuid, p_user_id uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
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
      )
      AND NOT EXISTS (
          SELECT 1 FROM asset_access_grants aag
          WHERE aag.asset_id = uaa.asset_id AND aag.user_id = p_user_id
      );
END;
$$;

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
      AND (gm.expires_at IS NULL OR gm.expires_at > now())
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
      AND (gm.expires_at IS NULL OR gm.expires_at > now())
    UNION
    SELECT DISTINCT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    WHERE principal_is_active(aag.tenant_id, aag.user_id)
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$function$;

CREATE OR REPLACE FUNCTION public.refresh_user_accessible_assets_for_tenant(p_tenant_id uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    DELETE FROM user_accessible_assets WHERE tenant_id = p_tenant_id;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE AND g.tenant_id = p_tenant_id
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = g.tenant_id
    WHERE principal_is_active(g.tenant_id, gm.user_id)
      AND (gm.expires_at IS NULL OR gm.expires_at > now())
    UNION
    SELECT DISTINCT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    WHERE aag.tenant_id = p_tenant_id
      AND principal_is_active(aag.tenant_id, aag.user_id)
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$function$;

DROP FUNCTION IF EXISTS public.refresh_access_for_owner_add(uuid, uuid);

DROP FUNCTION IF EXISTS public.refresh_access_for_owner_remove(uuid, uuid);

DROP VIEW IF EXISTS public.v_asset_owner_scope;

-- Creator grants stay as manual grants (the access they give is kept).

UPDATE public.asset_access_grants SET source = 'manual' WHERE source = 'creator';

ALTER TABLE public.asset_access_grants DROP CONSTRAINT IF EXISTS chk_asset_access_grants_source;

ALTER TABLE public.asset_access_grants ADD CONSTRAINT chk_asset_access_grants_source CHECK (source IN ('manual', 'migration'));

COMMENT ON TABLE public.asset_access_grants IS 'Explicit per-user data-scope grants (Layer 2). Being an asset owner does not grant access; groups and these grants do.';

COMMENT ON COLUMN public.asset_owners.assignment_source IS 'manual (set by a person), scope_rule (group scope rule), owner_ref (matched from assets.owner_ref; never grants data access)';

COMMENT ON TABLE public.user_accessible_assets IS 'Denormalized view of which assets a user can access through group membership';

-- Ownership-only rows go.

SELECT refresh_user_accessible_assets();
