-- Remove group permission sets and per-group permission overrides.
--
-- Permissions come only from roles; groups carry only data scope (which
-- assets their members see). Permission sets (permission_sets and their
-- items and versions), their assignment to groups (group_permission_sets)
-- and per-group permission overrides (group_permissions) were never read by
-- enforcement, so they granted nothing while the UI said members inherit
-- them. This migration removes them.
--
-- Live data: every row of the dropped tables, the three team:permission_sets:*
-- catalog rows and their role grants is copied, as JSON, into
-- access_control_removed_archive before anything is dropped, so the down
-- migration restores them exactly. The archive is created only when there is
-- something to keep.

CREATE TEMP TABLE removed_permission_ids (id VARCHAR(100) PRIMARY KEY) ON COMMIT DROP;
INSERT INTO removed_permission_ids (id) VALUES
    ('team:permission_sets:read'),
    ('team:permission_sets:write'),
    ('team:permission_sets:delete');

DO $$
DECLARE
    n BIGINT := 0;
BEGIN
    IF to_regclass('public.permission_sets') IS NOT NULL THEN
        SELECT n + (SELECT count(*) FROM permission_sets)
                 + (SELECT count(*) FROM permission_set_items)
                 + (SELECT count(*) FROM permission_set_versions)
                 + (SELECT count(*) FROM group_permission_sets)
          INTO n;
    END IF;
    IF to_regclass('public.group_permissions') IS NOT NULL THEN
        SELECT n + (SELECT count(*) FROM group_permissions) INTO n;
    END IF;
    SELECT n + (SELECT count(*) FROM permissions WHERE id IN (SELECT id FROM removed_permission_ids))
             + (SELECT count(*) FROM role_permissions WHERE permission_id IN (SELECT id FROM removed_permission_ids))
      INTO n;

    RAISE NOTICE 'removing group permission sets: % rows to archive', n;
    IF n = 0 THEN
        RETURN;
    END IF;

    CREATE TABLE IF NOT EXISTS access_control_removed_archive (
        id           BIGSERIAL PRIMARY KEY,
        source_table TEXT        NOT NULL,
        row_data     JSONB       NOT NULL,
        archived_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    COMMENT ON TABLE access_control_removed_archive IS
        'Rows removed by migration 000465 (group permission sets); restored by its down migration';

    IF to_regclass('public.permission_sets') IS NOT NULL THEN
        INSERT INTO access_control_removed_archive (source_table, row_data)
        SELECT 'permission_sets', to_jsonb(t) FROM permission_sets t;
        INSERT INTO access_control_removed_archive (source_table, row_data)
        SELECT 'permission_set_items', to_jsonb(t) FROM permission_set_items t;
        INSERT INTO access_control_removed_archive (source_table, row_data)
        SELECT 'permission_set_versions', to_jsonb(t) FROM permission_set_versions t;
        INSERT INTO access_control_removed_archive (source_table, row_data)
        SELECT 'group_permission_sets', to_jsonb(t) FROM group_permission_sets t;
    END IF;
    IF to_regclass('public.group_permissions') IS NOT NULL THEN
        INSERT INTO access_control_removed_archive (source_table, row_data)
        SELECT 'group_permissions', to_jsonb(t) FROM group_permissions t;
    END IF;
    INSERT INTO access_control_removed_archive (source_table, row_data)
    SELECT 'permissions', to_jsonb(t) FROM permissions t
    WHERE t.id IN (SELECT id FROM removed_permission_ids);
    INSERT INTO access_control_removed_archive (source_table, row_data)
    SELECT 'role_permissions', to_jsonb(t) FROM role_permissions t
    WHERE t.permission_id IN (SELECT id FROM removed_permission_ids);
END $$;

DROP TABLE IF EXISTS group_permission_sets;
DROP TABLE IF EXISTS permission_set_versions;
DROP TABLE IF EXISTS permission_set_items;
DROP TABLE IF EXISTS permission_sets;
DROP TABLE IF EXISTS group_permissions;

-- role_permissions rows go with the catalog rows (ON DELETE CASCADE).
DELETE FROM permissions WHERE id IN (SELECT id FROM removed_permission_ids);
