ALTER TABLE tenant_invitations
    DROP CONSTRAINT IF EXISTS chk_tenant_invitations_expiry_reason_len,
    DROP COLUMN IF EXISTS access_expiry_reason,
    DROP COLUMN IF EXISTS access_expires_at;

DROP TRIGGER IF EXISTS trigger_refuse_external_owner_member ON tenant_members;
DROP FUNCTION IF EXISTS refuse_external_owner_member();
DROP TRIGGER IF EXISTS trigger_refuse_external_owner_role ON user_roles;
DROP FUNCTION IF EXISTS refuse_external_owner_role();

DROP INDEX IF EXISTS idx_tenant_members_expiry;
DROP INDEX IF EXISTS idx_tenant_members_home;

ALTER TABLE tenant_members
    DROP CONSTRAINT IF EXISTS chk_tenant_members_expiry_reason_len,
    DROP CONSTRAINT IF EXISTS chk_tenant_members_external_not_owner,
    DROP CONSTRAINT IF EXISTS chk_tenant_members_kind,
    DROP COLUMN IF EXISTS suspended_reason,
    DROP COLUMN IF EXISTS expiry_reason,
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS home_domain,
    DROP COLUMN IF EXISTS home_tenant_id,
    DROP COLUMN IF EXISTS kind;
