-- scans:tenant_tools:delete gates nothing any more: the tool settings have no
-- delete (one PATCH .../settings), and custom capabilities are deleted with
-- scans:tools:delete, as custom tools are. A permission that gates nothing
-- still shows in the role editor, so it is removed
-- (tests/unit/permission_checked_test.go). No role loses access to anything:
-- no route checks it.
--
-- The catalog row and its role grants are copied, as JSON, into
-- access_control_removed_archive first; the down migration restores them.

-- A temp table: gone at the end of the session.
CREATE TEMP TABLE IF NOT EXISTS removed_permission_ids_001179 (id VARCHAR(100) PRIMARY KEY);
INSERT INTO removed_permission_ids_001179 (id) VALUES
    ('scans:tenant_tools:delete')
ON CONFLICT DO NOTHING;

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'permissions:001179', to_jsonb(t) FROM permissions t
WHERE t.id IN (SELECT id FROM removed_permission_ids_001179);

INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'role_permissions:001179', to_jsonb(t) FROM role_permissions t
WHERE t.permission_id IN (SELECT id FROM removed_permission_ids_001179);

-- role_permissions rows go with the catalog row (ON DELETE CASCADE).
DELETE FROM permissions WHERE id IN (SELECT id FROM removed_permission_ids_001179);
