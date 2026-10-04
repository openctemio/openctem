-- =============================================================================
-- Migration 000372: asset owner is not a data-scope grant
-- =============================================================================
-- Owner decision O1 (research 12, 2026-10-03). Until now naming a user as an
-- owner of an asset (asset_owners.user_id, Owners tab, assets:write) also put
-- the asset in that user's data scope (user_accessible_assets "Path B"). An
-- inventory edit silently changed what another user can see.
--
-- From now on an owner is an assignment only. A user's data scope comes from:
--
--   * Path A, unchanged: the user's active groups and the assets assigned to
--     those groups (asset_owners rows with group_id: group asset assignment
--     and scope rules, both groups:write);
--   * Path C, new: explicit per-user grants in asset_access_grants, managed
--     with groups:write (GET/POST/DELETE /api/v1/assets/{id}/access-grants).
--
-- Migration safety: every user who can see an asset TODAY because they are a
-- direct owner of it keeps that access. For each direct user owner row (source
-- manual or scope_rule; owner_ref rows never granted access) whose user is a
-- member of the asset's tenant and already has the asset in
-- user_accessible_assets, an equivalent grant (source 'migration') is created.
-- user_accessible_assets itself is not changed by this migration. The counts
-- are written to the database log.
--
-- Live-database safety: CREATE TABLE plus a keyset-batched INSERT (5000 owner
-- rows per batch); existing tables are only read, and the functions are
-- replaced in place. Re-runnable.
-- =============================================================================

CREATE TABLE IF NOT EXISTS asset_access_grants (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id   UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source     VARCHAR(20) NOT NULL DEFAULT 'manual',
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_asset_access_grants_source CHECK (source IN ('manual', 'migration')),
    CONSTRAINT uq_asset_access_grants_asset_user UNIQUE (asset_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_access_grants_tenant_user ON asset_access_grants (tenant_id, user_id);

COMMENT ON TABLE asset_access_grants IS
    'Explicit per-user data-scope grants (Layer 2). Being an asset owner does not grant access; groups and these grants do.';

-- RLS policy in shadow mode, like every tenant-scoped table (000157/000158).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies
                   WHERE tablename = 'asset_access_grants'
                     AND policyname = 'asset_access_grants_tenant_isolation') THEN
        CREATE POLICY asset_access_grants_tenant_isolation ON asset_access_grants
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
                   OR current_setting('app.is_platform_admin', true) = 'true');
    END IF;
END $$;

-- Preserve today's owner-derived access as explicit grants.
DO $$
DECLARE
    cursor_id     uuid := NULL;
    last_id       uuid;
    batch_rows    int;
    created       bigint := 0;
    owner_only    bigint;
    not_effective bigint;
BEGIN
    LOOP
        SELECT page.id INTO last_id FROM (
            SELECT id FROM asset_owners
            WHERE user_id IS NOT NULL
              AND (cursor_id IS NULL OR id > cursor_id)
            ORDER BY id
            LIMIT 5000
        ) page
        ORDER BY page.id DESC
        LIMIT 1;
        EXIT WHEN last_id IS NULL;

        INSERT INTO asset_access_grants (tenant_id, asset_id, user_id, source, granted_by, granted_at)
        SELECT a.tenant_id, ao.asset_id, ao.user_id, 'migration', ao.assigned_by, COALESCE(ao.assigned_at, NOW())
        FROM asset_owners ao
        JOIN assets a ON a.id = ao.asset_id
        JOIN tenant_members tm ON tm.user_id = ao.user_id AND tm.tenant_id = a.tenant_id
        JOIN user_accessible_assets uaa
          ON uaa.user_id = ao.user_id AND uaa.tenant_id = a.tenant_id AND uaa.asset_id = ao.asset_id
        WHERE ao.user_id IS NOT NULL
          AND ao.assignment_source IS DISTINCT FROM 'owner_ref'
          AND (cursor_id IS NULL OR ao.id > cursor_id)
          AND ao.id <= last_id
        ON CONFLICT (asset_id, user_id) DO NOTHING;
        GET DIAGNOSTICS batch_rows = ROW_COUNT;
        created := created + batch_rows;

        cursor_id := last_id;
    END LOOP;

    -- Of those, the pairs no group gives access to: without the grant these
    -- users would have lost the asset.
    SELECT count(*) INTO owner_only
    FROM asset_access_grants g
    WHERE g.source = 'migration'
      AND NOT EXISTS (
          SELECT 1 FROM group_members gm
          JOIN groups gr ON gr.id = gm.group_id AND gr.is_active = TRUE
          JOIN asset_owners ao ON ao.group_id = gm.group_id AND ao.asset_id = g.asset_id
          WHERE gm.user_id = g.user_id);

    -- Direct owners that had no access row (never granted, e.g. a failed
    -- refresh): no grant, so nobody gains access through this migration.
    SELECT count(*) INTO not_effective
    FROM asset_owners ao
    JOIN assets a ON a.id = ao.asset_id
    WHERE ao.user_id IS NOT NULL
      AND ao.assignment_source IS DISTINCT FROM 'owner_ref'
      AND NOT EXISTS (SELECT 1 FROM asset_access_grants g
                      WHERE g.asset_id = ao.asset_id AND g.user_id = ao.user_id);

    RAISE LOG 'asset access grants: % grants created from direct ownership (% of them were the only access path); % direct owners had no access and got no grant',
        created, owner_only, not_effective;
END $$;

-- Full refresh: groups (Path A) plus explicit grants (Path C). Direct
-- ownership is no longer an access path.
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

-- Grant added: the user sees the asset.
CREATE OR REPLACE FUNCTION refresh_access_for_grant_add(p_asset_id UUID, p_user_id UUID)
RETURNS void AS $$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    WHERE aag.asset_id = p_asset_id AND aag.user_id = p_user_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- Grant removed: the access row goes unless a group still gives access.
CREATE OR REPLACE FUNCTION refresh_access_for_grant_remove(p_asset_id UUID, p_user_id UUID)
RETURNS void AS $$
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
$$ LANGUAGE plpgsql;

-- Direct ownership no longer grants access. Kept (as a no-op) so a pod of the
-- previous release that still calls it during a rollout grants nothing.
CREATE OR REPLACE FUNCTION refresh_access_for_direct_owner_add(
    p_asset_id UUID, p_user_id UUID, p_ownership_type VARCHAR
) RETURNS void AS $$
BEGIN
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Kept for a pod of the previous release: removing a direct owner drops the
-- access row only when neither a group nor a grant gives access.
CREATE OR REPLACE FUNCTION refresh_access_for_direct_owner_remove(
    p_asset_id UUID, p_user_id UUID
) RETURNS void AS $$
BEGIN
    PERFORM refresh_access_for_grant_remove(p_asset_id, p_user_id);
END;
$$ LANGUAGE plpgsql;

-- Group paths: a user with an explicit grant keeps access when a group loses
-- the asset or the user leaves a group.
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
      )
      AND NOT EXISTS (
          SELECT 1 FROM asset_access_grants aag
          WHERE aag.asset_id = p_asset_id AND aag.user_id = uaa.user_id
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
      )
      AND NOT EXISTS (
          SELECT 1 FROM asset_access_grants aag
          WHERE aag.asset_id = uaa.asset_id AND aag.user_id = p_user_id
      );
END;
$$ LANGUAGE plpgsql;
