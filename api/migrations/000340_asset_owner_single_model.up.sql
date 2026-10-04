-- =============================================================================
-- Migration 000340: one asset owner model (asset_owners is the source of truth)
-- =============================================================================
-- Owner decision O2 (research 12, 2026-10-03). Until now an asset had two
-- unrelated owner stores:
--
--   * assets.owner_id: one user, set only by matching owner_ref (an email from
--     ingest or the asset form) to a member of the tenant;
--   * asset_owners: the RACI table (users or groups, with an ownership type),
--     set on the asset's Owners tab, by group asset assignment and by scope
--     rules.
--
-- This migration copies every assets.owner_id into asset_owners, so that the
-- application can read owners from asset_owners only:
--
--   * ownership_type 'primary': owner_id meant "the user who owns this asset",
--     which is the RACI primary (accountable) owner. The finding auto-assign
--     action already treated the primary user owner as the same person;
--   * assignment_source 'owner_ref': the row was derived from owner_ref, not
--     set by a person. The application re-derives these rows when owner_ref
--     changes, and leaves 'manual' and 'scope_rule' rows alone;
--   * a user who is already an owner of the asset (any ownership type) keeps
--     their existing row: an explicit RACI choice is never overwritten;
--   * a user who is no longer a member of the asset's tenant is not copied
--     (the owner_ref auto-match only ever matched members). owner_ref itself is
--     kept, so the owner is matched again if they rejoin.
--
-- Data scope does not change. assets.owner_id never granted data access, so the
-- copied rows must not either: refresh_user_accessible_assets() and
-- refresh_access_for_direct_owner_remove() skip 'owner_ref' rows (see below).
-- user_accessible_assets is not touched by this migration.
--
-- Live-database safety: asset_owners rows are inserted in keyset batches of
-- 5000 assets; assets is only read. No lock beyond ROW EXCLUSIVE on
-- asset_owners. Re-runnable (ON CONFLICT DO NOTHING plus NOT EXISTS).
-- The column itself is dropped by a later contract migration, after a
-- release (expand-contract: pods of the previous release still read it).
-- =============================================================================

DO $$
DECLARE
    cursor_id   uuid := NULL;
    last_id     uuid;
    batch_rows  int;
    copied      bigint := 0;
    kept        bigint;
    not_member  bigint;
BEGIN
    LOOP
        SELECT page.id INTO last_id FROM (
            SELECT id FROM assets
            WHERE owner_id IS NOT NULL
              AND (cursor_id IS NULL OR id > cursor_id)
            ORDER BY id
            LIMIT 5000
        ) page
        ORDER BY page.id DESC
        LIMIT 1;
        EXIT WHEN last_id IS NULL;

        INSERT INTO asset_owners (asset_id, user_id, ownership_type, assigned_at, assignment_source)
        SELECT a.id, a.owner_id, 'primary', COALESCE(a.updated_at, NOW()), 'owner_ref'
        FROM assets a
        JOIN tenant_members tm ON tm.user_id = a.owner_id AND tm.tenant_id = a.tenant_id
        WHERE a.owner_id IS NOT NULL
          AND (cursor_id IS NULL OR a.id > cursor_id)
          AND a.id <= last_id
          AND NOT EXISTS (
              SELECT 1 FROM asset_owners ao
              WHERE ao.asset_id = a.id AND ao.user_id = a.owner_id
          )
        ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS batch_rows = ROW_COUNT;
        copied := copied + batch_rows;

        cursor_id := last_id;
    END LOOP;

    SELECT count(*) INTO kept
    FROM assets a
    JOIN asset_owners ao ON ao.asset_id = a.id AND ao.user_id = a.owner_id
    WHERE ao.assignment_source IS DISTINCT FROM 'owner_ref';

    SELECT count(*) INTO not_member
    FROM assets a
    WHERE a.owner_id IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM tenant_members tm
                      WHERE tm.user_id = a.owner_id AND tm.tenant_id = a.tenant_id);

    RAISE LOG 'asset owner single model: % owner_id values copied to asset_owners as primary; % already had an explicit asset_owners row (kept as is); % skipped (owner no longer a member of the tenant)',
        copied, kept, not_member;
END $$;

-- Full refresh of user_accessible_assets. Path B (a user named directly as an
-- owner) skips rows derived from owner_ref: they replace assets.owner_id, which
-- never granted data access.
CREATE OR REPLACE FUNCTION refresh_user_accessible_assets()
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    -- Path A: group-based access
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    UNION
    -- Path B: direct user ownership set by a person
    SELECT DISTINCT ao.user_id, a.tenant_id, ao.asset_id, ao.ownership_type
    FROM asset_owners ao
    JOIN assets a ON a.id = ao.asset_id
    WHERE ao.user_id IS NOT NULL
      AND ao.assignment_source IS DISTINCT FROM 'owner_ref'
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- Incremental refresh on direct owner removal: an 'owner_ref' row is not an
-- access path, so it does not keep the user's access alive.
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

COMMENT ON COLUMN asset_owners.assignment_source IS
    'manual (set by a person), scope_rule (group scope rule), owner_ref (matched from assets.owner_ref; never grants data access)';
