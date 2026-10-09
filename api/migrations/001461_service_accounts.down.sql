-- Service accounts go with the kind column: remove them first.
DELETE FROM users WHERE kind = 'service';
DROP TRIGGER IF EXISTS trigger_refuse_service_account_privileged_role ON user_roles;
DROP FUNCTION IF EXISTS refuse_service_account_privileged_role();
DROP TRIGGER IF EXISTS trigger_refuse_service_account_membership ON tenant_members;
DROP FUNCTION IF EXISTS refuse_service_account_membership();
DROP INDEX IF EXISTS idx_users_service_tenant;
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS chk_users_service_account,
    DROP CONSTRAINT IF EXISTS chk_users_kind,
    DROP COLUMN IF EXISTS service_owner_id,
    DROP COLUMN IF EXISTS service_tenant_id,
    DROP COLUMN IF EXISTS kind;
