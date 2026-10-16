-- findings:lifecycles:write manages an organization's finding lifecycles:
-- sub-statuses and lifecycle schemes (docs/rfcs/RFC-110-tenant-lifecycles.md).
-- Owner and admin by default, assignable to custom roles.
INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('findings:lifecycles:write', 'findings', 'Manage Finding Lifecycles',
     'Create and change finding sub-statuses and lifecycle schemes; publishing also needs a recent sign-in', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'findings:lifecycles:write'
FROM roles r
WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (role_id, permission_id) DO NOTHING;
