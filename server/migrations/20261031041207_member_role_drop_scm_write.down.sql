INSERT INTO role_permissions (role_id, permission_id)
VALUES ('00000000-0000-0000-0000-000000000003', 'integrations:scm:write')
ON CONFLICT (role_id, permission_id) DO NOTHING;
