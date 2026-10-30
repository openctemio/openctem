ALTER TABLE role_permissions DROP CONSTRAINT IF EXISTS role_permissions_not_platform_namespace;
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_not_platform_namespace;
DROP TRIGGER IF EXISTS trg_sync_platform_base_role ON admin_users;
DROP FUNCTION IF EXISTS sync_platform_base_role();
DROP TABLE IF EXISTS platform_role_assignments;
DROP TABLE IF EXISTS platform_role_permissions;
DROP TABLE IF EXISTS platform_roles;
