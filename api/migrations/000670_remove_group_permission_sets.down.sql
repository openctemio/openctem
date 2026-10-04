-- Restore the team:permission_sets:* catalog rows and their role grants from
-- the archive the up migration wrote. Grants of a role that no longer exists
-- are skipped.

INSERT INTO permissions
SELECT r.*
FROM access_control_removed_archive a,
     jsonb_populate_record(NULL::permissions, a.row_data) r
WHERE a.source_table = 'permissions'
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions
SELECT r.*
FROM access_control_removed_archive a,
     jsonb_populate_record(NULL::role_permissions, a.row_data) r
WHERE a.source_table = 'role_permissions'
  AND EXISTS (SELECT 1 FROM roles ro WHERE ro.id = r.role_id)
  AND EXISTS (SELECT 1 FROM permissions p WHERE p.id = r.permission_id)
ON CONFLICT DO NOTHING;

DROP TABLE IF EXISTS access_control_removed_archive;

COMMENT ON TABLE permission_sets IS 'Permission set definitions with inheritance support';
COMMENT ON TABLE group_permission_sets IS 'Maps permission sets to groups';
COMMENT ON TABLE group_permissions IS 'Per-group permission overrides with optional scope filtering';
