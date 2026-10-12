INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000004', p.id
FROM (VALUES ('scans:secret_store:read'), ('team:assignment_rules:read')) AS p(id)
ON CONFLICT (role_id, permission_id) DO NOTHING;
