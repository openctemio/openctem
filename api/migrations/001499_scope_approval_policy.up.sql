-- The platform policy for scope-widening approvals (RFC-054 §12.6): a
-- per-organization override set only by a platform administrator (NULL:
-- the platform default in platform_settings 'scope_approval_policy', itself
-- 'required' when not stored). No tenant route writes this column.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS scope_approval_policy varchar(32) NULL;

ALTER TABLE tenants
    ADD CONSTRAINT chk_tenants_scope_approval_policy
    CHECK (scope_approval_policy IS NULL OR scope_approval_policy IN ('required', 'tenant_controlled', 'disabled'));

COMMENT ON COLUMN tenants.scope_approval_policy IS 'Platform administrator override of the scope-widening approval policy (RFC-054 §12.6); NULL follows the platform default';
