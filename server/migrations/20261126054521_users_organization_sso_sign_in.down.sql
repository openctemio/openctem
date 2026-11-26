ALTER TABLE users
    DROP COLUMN IF EXISTS sso_tenant_id,
    DROP COLUMN IF EXISTS sso_signed_in_at;
