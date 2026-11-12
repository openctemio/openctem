-- Restore sensors:commands:delete and grant it to the system owner and
-- administrator roles (the roles the catalog granted it to). API key scopes
-- and licenses do not get it back.
INSERT INTO permissions (id, module_id, name, description, is_active)
VALUES ('sensors:commands:delete', 'sensors', 'Delete Commands', 'Remove sensor commands', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'sensors:commands:delete'
FROM roles r
WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
ON CONFLICT DO NOTHING;
