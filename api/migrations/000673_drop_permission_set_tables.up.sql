-- expand-contract-ok: contract step of 000670; no code has read or written these tables since that release
--
-- Drop the group permission-set tables. Permissions come only from roles;
-- groups carry only data scope. Migration 000670 (the expand step) removed
-- every code path that read or wrote permission_sets, permission_set_items,
-- permission_set_versions, group_permission_sets and group_permissions, and
-- the team:permission_sets:* permissions. Merge this only after a release
-- containing 000670, so no running pod still queries the tables.
--
-- Live data: every row of the dropped tables is copied, as JSON, into
-- access_control_removed_archive (created by 000670) before anything is
-- dropped, so the down migration restores them exactly.

CREATE TABLE IF NOT EXISTS access_control_removed_archive (
    id           BIGSERIAL PRIMARY KEY,
    source_table TEXT        NOT NULL,
    row_data     JSONB       NOT NULL,
    archived_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
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
END $$;

DROP TABLE IF EXISTS group_permission_sets;
DROP TABLE IF EXISTS permission_set_versions;
DROP TABLE IF EXISTS permission_set_items;
DROP TABLE IF EXISTS permission_sets;
DROP TABLE IF EXISTS group_permissions;
