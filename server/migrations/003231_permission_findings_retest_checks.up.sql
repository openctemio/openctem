-- findings:retest_checks:write attaches, changes and removes a finding's
-- retest check (docs/architecture/finding-retest-checks.md). Owner and admin
-- by default; the security role templates carry it; assignable to custom roles.
INSERT INTO permissions (id, module_id, name, description, is_active) VALUES
    ('findings:retest_checks:write', 'findings', 'Manage Finding Retest Checks',
     'Attach, change and remove the custom check a finding''s retest runs', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'findings:retest_checks:write'
FROM roles r
WHERE r.id IN ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002')
ON CONFLICT (role_id, permission_id) DO NOTHING;
