ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_scan_approval_policy;
UPDATE tenants SET scan_approval_policy = CASE scan_approval_policy WHEN 'off' THEN 'disabled' ELSE NULL END
 WHERE scan_approval_policy IS NOT NULL;
ALTER TABLE tenants RENAME COLUMN scan_approval_policy TO scope_approval_policy;
ALTER TABLE tenants
    ADD CONSTRAINT chk_tenants_scope_approval_policy
    CHECK (scope_approval_policy IS NULL OR scope_approval_policy IN ('required', 'tenant_controlled', 'disabled'));
COMMENT ON COLUMN tenants.scope_approval_policy IS 'Platform administrator override of the scope-widening approval policy (RFC-054 §12.6); NULL follows the platform default';
DELETE FROM platform_settings WHERE key = 'scan_approval_policy';
