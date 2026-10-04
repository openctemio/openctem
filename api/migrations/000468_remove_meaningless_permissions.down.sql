-- Restore the removed catalog rows and their role grants from the archive.
INSERT INTO permissions
SELECT r.*
FROM access_control_removed_archive a,
     jsonb_populate_record(NULL::permissions, a.row_data) r
WHERE a.source_table = 'permissions:000468'
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions
SELECT r.*
FROM access_control_removed_archive a,
     jsonb_populate_record(NULL::role_permissions, a.row_data) r
WHERE a.source_table = 'role_permissions:000468'
  AND EXISTS (SELECT 1 FROM roles ro WHERE ro.id = r.role_id)
  AND EXISTS (SELECT 1 FROM permissions p WHERE p.id = r.permission_id)
ON CONFLICT DO NOTHING;

DELETE FROM access_control_removed_archive
WHERE source_table IN ('permissions:000468', 'role_permissions:000468');
