-- Revert Migration 000226.
DROP TRIGGER IF EXISTS trg_forbid_platform_admin_membership ON tenant_members;
DROP FUNCTION IF EXISTS forbid_platform_admin_membership();
DROP INDEX IF EXISTS idx_admin_users_user_id;
ALTER TABLE admin_users DROP COLUMN IF EXISTS user_id;
