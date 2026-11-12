-- Owning an asset grants view of it (docs/architecture/asset-ownership.md,
-- "Ownership and data scope").
--
-- A user who is a primary or secondary owner of an asset, set by a person
-- (assignment_source 'manual'), now has the asset in their data scope
-- (user_accessible_assets), so they see the asset and its findings on every
-- scoped read. What they may do there is still decided by their role.
-- Owners matched from assets.owner_ref (data from a source or an import) and
-- stakeholder / informed / regulatory owners grant nothing.
--
-- v_asset_owner_scope is the one definition; every scope refresh function
-- reads it, and asset_owners changes (insert, update of user / type /
-- source, delete) add or remove the affected (user, asset) row in the same
-- transaction, so removing an owner removes the access at once (unless a
-- group or an explicit grant still gives it).
--
-- Also: an asset access grant may have source 'creator' (a member who
-- creates an asset without full data access sees what they created).

CREATE OR REPLACE VIEW public.v_asset_owner_scope AS
SELECT ao.user_id, a.tenant_id, ao.asset_id, ao.ownership_type
FROM asset_owners ao
JOIN assets a ON a.id = ao.asset_id AND a.deleted_at IS NULL
WHERE ao.user_id IS NOT NULL
  AND ao.ownership_type IN ('primary', 'secondary')
  AND COALESCE(ao.assignment_source, 'manual') = 'manual';

COMMENT ON VIEW public.v_asset_owner_scope IS
    'User owners whose ownership puts the asset in their data scope: primary or secondary, assigned by a person (not owner_ref). The tenant is the asset''s.';

COMMENT ON TABLE public.asset_access_grants IS
    'Explicit per-user data-scope grants (Layer 2): manual (a person), migration, creator (the member who created the asset). Primary and secondary user owners set by a person are in scope through v_asset_owner_scope.';

ALTER TABLE public.asset_access_grants DROP CONSTRAINT IF EXISTS chk_asset_access_grants_source;
ALTER TABLE public.asset_access_grants ADD CONSTRAINT chk_asset_access_grants_source
    CHECK (source IN ('manual', 'migration', 'creator'));

COMMENT ON COLUMN public.asset_owners.assignment_source IS
    'manual (set by a person; a primary or secondary user owner gets the asset in their data scope), scope_rule (group scope rule), owner_ref (matched from assets.owner_ref; never grants data access)';

COMMENT ON TABLE public.user_accessible_assets IS
    'Denormalized data scope: assets a user can access through group membership, explicit grants and primary/secondary ownership (v_asset_owner_scope)';

-- Ownership added: the asset joins the owner's scope when the row grants it.
CREATE OR REPLACE FUNCTION public.refresh_access_for_owner_add(p_user_id uuid, p_asset_id uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT o.user_id, o.tenant_id, o.asset_id, o.ownership_type
    FROM v_asset_owner_scope o
    WHERE o.user_id = p_user_id AND o.asset_id = p_asset_id
      AND principal_is_active(o.tenant_id, o.user_id)
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$function$;

-- Ownership removed: the asset leaves the user's scope unless a group, an
-- explicit grant or a remaining ownership still gives it.
CREATE OR REPLACE FUNCTION public.refresh_access_for_owner_remove(p_user_id uuid, p_asset_id uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
    DELETE FROM user_accessible_assets uaa
    WHERE uaa.user_id = p_user_id AND uaa.asset_id = p_asset_id
      AND NOT EXISTS (
          SELECT 1 FROM group_members gm
          JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
          JOIN asset_owners ao ON ao.group_id = gm.group_id AND ao.asset_id = p_asset_id
          WHERE gm.user_id = p_user_id
            AND (gm.expires_at IS NULL OR gm.expires_at > now()))
      AND NOT EXISTS (
          SELECT 1 FROM asset_access_grants aag
          WHERE aag.asset_id = p_asset_id AND aag.user_id = p_user_id)
      AND NOT EXISTS (
          SELECT 1 FROM v_asset_owner_scope o
          WHERE o.asset_id = p_asset_id AND o.user_id = p_user_id);
END;
$function$;

CREATE OR REPLACE FUNCTION public.trg_asset_owners_scope_sync()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.group_id IS NOT NULL THEN
            PERFORM refresh_access_for_asset_assign(NEW.group_id, NEW.asset_id, NEW.ownership_type);
        END IF;
        IF NEW.user_id IS NOT NULL THEN
            PERFORM refresh_access_for_owner_add(NEW.user_id, NEW.asset_id);
        END IF;
        RETURN NEW;
    END IF;
    -- OLD granted scope: the v_asset_owner_scope predicate on the old row.
    IF OLD.user_id IS NOT NULL
       AND OLD.ownership_type IN ('primary', 'secondary')
       AND COALESCE(OLD.assignment_source, 'manual') = 'manual' THEN
        PERFORM refresh_access_for_owner_remove(OLD.user_id, OLD.asset_id);
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.user_id IS NOT NULL THEN
            PERFORM refresh_access_for_owner_add(NEW.user_id, NEW.asset_id);
        END IF;
        RETURN NEW;
    END IF;
    -- DELETE
    IF OLD.group_id IS NOT NULL THEN
        PERFORM refresh_access_for_asset_unassign(OLD.group_id, OLD.asset_id);
    END IF;
    RETURN OLD;
END;
$function$;

DROP TRIGGER IF EXISTS asset_owners_scope_sync ON public.asset_owners;
CREATE TRIGGER asset_owners_scope_sync
    AFTER INSERT OR DELETE OR UPDATE OF user_id, asset_id, ownership_type, assignment_source ON public.asset_owners
    FOR EACH ROW EXECUTE FUNCTION public.trg_asset_owners_scope_sync();

-- The removal paths keep a row that ownership still grants.
CREATE OR REPLACE FUNCTION public.refresh_access_for_asset_unassign(p_group_id uuid, p_asset_id uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
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
      )
      AND NOT EXISTS (
          SELECT 1 FROM v_asset_owner_scope o
          WHERE o.asset_id = p_asset_id AND o.user_id = uaa.user_id
      );
END;
$function$;

CREATE OR REPLACE FUNCTION public.refresh_access_for_grant_remove(p_asset_id uuid, p_user_id uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
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
          WHERE aag.asset_id = p_asset_id AND aag.user_id = p_user_id)
      AND NOT EXISTS (
          SELECT 1 FROM v_asset_owner_scope o
          WHERE o.asset_id = p_asset_id AND o.user_id = p_user_id);
END;
$function$;

CREATE OR REPLACE FUNCTION public.refresh_access_for_member_remove(p_group_id uuid, p_user_id uuid)
 RETURNS void
 LANGUAGE plpgsql
AS $function$
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
      )
      AND NOT EXISTS (
          SELECT 1 FROM v_asset_owner_scope o
          WHERE o.asset_id = uaa.asset_id AND o.user_id = p_user_id
      );
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
      AND (gm.expires_at IS NULL OR gm.expires_at > now())
    UNION
    SELECT DISTINCT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    WHERE aag.tenant_id = p_tenant_id AND aag.user_id = p_user_id
    UNION
    SELECT o.user_id, o.tenant_id, o.asset_id, o.ownership_type
    FROM v_asset_owner_scope o
    WHERE o.tenant_id = p_tenant_id AND o.user_id = p_user_id
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
    UNION
    SELECT o.user_id, o.tenant_id, o.asset_id, o.ownership_type
    FROM v_asset_owner_scope o
    WHERE principal_is_active(o.tenant_id, o.user_id)
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
    UNION
    SELECT o.user_id, o.tenant_id, o.asset_id, o.ownership_type
    FROM v_asset_owner_scope o
    WHERE o.tenant_id = p_tenant_id
      AND principal_is_active(o.tenant_id, o.user_id)
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$function$;

-- Existing primary and secondary owners set by a person get their assets now.
INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
SELECT o.user_id, o.tenant_id, o.asset_id, o.ownership_type
FROM v_asset_owner_scope o
WHERE principal_is_active(o.tenant_id, o.user_id)
ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
