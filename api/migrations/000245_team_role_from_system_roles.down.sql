-- Restores the pre-245 view and drops the custom-role constraints. The renamed
-- slugs and clamped hierarchy levels are not reverted: the old values are what
-- made a custom role pass for owner/admin.

ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_custom_level_below_admin;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_custom_slug_not_reserved;

DROP VIEW IF EXISTS v_user_effective_role;
CREATE VIEW v_user_effective_role AS
SELECT DISTINCT ON (ur.user_id, ur.tenant_id)
    ur.user_id,
    ur.tenant_id,
    r.slug AS role,
    r.name AS role_name,
    r.hierarchy_level,
    r.has_full_data_access
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
ORDER BY ur.user_id, ur.tenant_id, r.hierarchy_level DESC;

COMMENT ON VIEW v_user_effective_role IS
    'Returns the highest-priority role for each user in each tenant';

COMMENT ON COLUMN roles.hierarchy_level IS 'Higher level = more privileges (owner=100, admin=80, member=50, viewer=20)';
