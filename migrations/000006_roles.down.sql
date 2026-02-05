-- =============================================================================
-- Migration 006: Roles and RBAC (Down)
-- =============================================================================

DROP FUNCTION IF EXISTS user_has_full_data_access(UUID, UUID);
DROP FUNCTION IF EXISTS user_has_permission(UUID, UUID, VARCHAR);
DROP FUNCTION IF EXISTS get_user_permissions(UUID, UUID);

DROP TRIGGER IF EXISTS trigger_roles_updated_at ON roles;

DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
