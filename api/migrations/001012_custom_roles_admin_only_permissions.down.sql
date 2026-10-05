-- Reverts 001012: drops the trigger and puts the stripped admin-only
-- permissions back on the custom roles that still exist (from the report
-- table the up migration kept). Roles deleted since are skipped.

DROP TRIGGER IF EXISTS trg_role_permissions_admin_only ON role_permissions;
DROP FUNCTION IF EXISTS refuse_admin_only_permission_on_custom_role();

INSERT INTO role_permissions (role_id, permission_id)
SELECT s.role_id, s.permission_id
FROM role_permissions_admin_only_stripped s
JOIN roles r ON r.id = s.role_id
JOIN permissions p ON p.id = s.permission_id
ON CONFLICT (role_id, permission_id) DO NOTHING;

DROP TABLE IF EXISTS role_permissions_admin_only_stripped;
