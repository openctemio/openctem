-- Restore assets:components:delete and grant it to every role that holds
-- assets:components:write (the roles the catalog granted both to). API key
-- scopes and licenses do not get it back.
INSERT INTO permissions (id, module_id, name, description, is_active)
VALUES ('assets:components:delete', 'components', 'Delete Components', 'Remove components', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, 'assets:components:delete'
FROM role_permissions rp
WHERE rp.permission_id = 'assets:components:write'
ON CONFLICT DO NOTHING;
