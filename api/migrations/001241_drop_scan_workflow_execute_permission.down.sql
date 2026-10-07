-- Restore integrations:pipelines:execute, its role grants and its
-- backfill-ledger rows from the archive. API key scopes do not get it back.
INSERT INTO permissions
SELECT r.*
FROM access_control_removed_archive a,
     jsonb_populate_record(NULL::permissions, a.row_data) r
WHERE a.source_table = 'permissions:001241'
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions
SELECT r.*
FROM access_control_removed_archive a,
     jsonb_populate_record(NULL::role_permissions, a.row_data) r
WHERE a.source_table = 'role_permissions:001241'
  AND EXISTS (SELECT 1 FROM roles ro WHERE ro.id = r.role_id)
  AND EXISTS (SELECT 1 FROM permissions p WHERE p.id = r.permission_id)
ON CONFLICT DO NOTHING;

INSERT INTO granular_permission_backfill
SELECT r.*
FROM access_control_removed_archive a,
     jsonb_populate_record(NULL::granular_permission_backfill, a.row_data) r
WHERE a.source_table = 'granular_permission_backfill:001241'
ON CONFLICT DO NOTHING;

DELETE FROM access_control_removed_archive
WHERE source_table IN ('permissions:001241', 'role_permissions:001241', 'granular_permission_backfill:001241');
