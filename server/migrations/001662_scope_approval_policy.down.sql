ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_scope_approval_policy;
ALTER TABLE tenants DROP COLUMN IF EXISTS scope_approval_policy;
DELETE FROM platform_settings WHERE key = 'scope_approval_policy';
