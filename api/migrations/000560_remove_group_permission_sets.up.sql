-- Group permission sets are removed: permissions come only from roles, and
-- groups carry only data scope (which assets their members see).
--
-- Expand step. The code no longer reads or writes permission_sets,
-- permission_set_items, permission_set_versions, group_permission_sets or
-- group_permissions; the tables stay so pods still running the previous
-- release keep working during a rolling deploy. A later migration drops
-- them, after a release, archiving their rows first.
--
-- This migration only takes the three team:permission_sets:* permissions out
-- of the catalog (their role grants go with them, ON DELETE CASCADE). They
-- gated nothing but the removed permission-set routes. The catalog rows and
-- the role grants are copied, as JSON, into access_control_removed_archive
-- first, so the down migration restores them exactly.

-- A session temp table (no ON COMMIT DROP: some runners apply a file
-- statement by statement); it goes away with the migration session.
CREATE TEMP TABLE IF NOT EXISTS removed_permission_ids (id VARCHAR(100) PRIMARY KEY);
INSERT INTO removed_permission_ids (id) VALUES
    ('team:permission_sets:read'),
    ('team:permission_sets:write'),
    ('team:permission_sets:delete')
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS access_control_removed_archive (
    id           BIGSERIAL PRIMARY KEY,
    source_table TEXT        NOT NULL,
    row_data     JSONB       NOT NULL,
    archived_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE access_control_removed_archive IS
    'Rows removed with group permission sets (migration 000560 and its contract step); restored by their down migrations';

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'permissions', to_jsonb(t) FROM permissions t
WHERE t.id IN (SELECT id FROM removed_permission_ids);

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'role_permissions', to_jsonb(t) FROM role_permissions t
WHERE t.permission_id IN (SELECT id FROM removed_permission_ids);

DELETE FROM permissions WHERE id IN (SELECT id FROM removed_permission_ids);

COMMENT ON TABLE permission_sets IS 'Unused since migration 000560 (permissions come only from roles); dropped by a later migration';
COMMENT ON TABLE group_permission_sets IS 'Unused since migration 000560 (permissions come only from roles); dropped by a later migration';
COMMENT ON TABLE group_permissions IS 'Unused since migration 000560 (permissions come only from roles); dropped by a later migration';
