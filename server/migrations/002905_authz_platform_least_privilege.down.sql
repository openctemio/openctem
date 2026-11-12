-- Restores the grants removed by the up migration.

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'sensors:read'
FROM roles r
WHERE r.template_id = 'researcher' AND NOT r.is_system AND r.template_version = 2
ON CONFLICT (role_id, permission_id) DO NOTHING;

UPDATE roles
SET template_permissions = array_append(template_permissions, 'sensors:read'),
    template_version = 1
WHERE template_id = 'researcher' AND NOT is_system AND template_version = 2
  AND NOT ('sensors:read' = ANY (template_permissions));

INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003'::uuid, 'scans:secret_store:write'
WHERE EXISTS (SELECT 1 FROM roles WHERE id = '00000000-0000-0000-0000-000000000003')
ON CONFLICT (role_id, permission_id) DO NOTHING;

ALTER TABLE integration_notification_extensions ALTER COLUMN include_details DROP NOT NULL;
ALTER TABLE integration_notification_extensions ALTER COLUMN include_details SET DEFAULT true;
-- Rows backfilled by the up migration stay: they hold the behaviour those channels had.
