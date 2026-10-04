-- dashboard:aggregate — organization-wide dashboard totals for a viewer whose
-- data scope is restricted (owner decision D6, research doc 15 P1-4).
--
-- Without it, a restricted viewer's dashboard counts only the assets and
-- findings in their own scope. Owners and admins see everything anyway; the
-- grant here keeps their role pages honest. Custom roles (an executive or
-- auditor role) get it only when a tenant adds it.
INSERT INTO permissions (id, module_id, name, description) VALUES
    ('dashboard:aggregate', 'dashboard', 'View Organization Totals', 'See organization-wide dashboard totals even with a restricted data scope (breakdowns under 5 are hidden)')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, 'dashboard:aggregate'
FROM (VALUES
    ('00000000-0000-0000-0000-000000000001'::uuid), -- owner
    ('00000000-0000-0000-0000-000000000002'::uuid)  -- admin
) AS r(role_id)
ON CONFLICT DO NOTHING;
