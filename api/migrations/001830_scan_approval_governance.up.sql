-- Scan approval governance (docs/rfcs/RFC-072-scan-approval-governance.md).
--
-- The platform administrator's per-organization policy now governs scan
-- approval (tenant_controlled, off, on, strict) instead of scope-entry
-- approvals: tenants.scope_approval_policy becomes scan_approval_policy.
-- Old overrides map as: disabled -> off; required and tenant_controlled ->
-- NULL (the platform default, tenant_controlled: the organization chooses,
-- Off unless its owner turns it on). The stored platform default is dropped
-- for the same reason. The organization's own choice lives in
-- tenants.settings -> scan_governance (no schema change).

-- expand-contract-ok: one-step rename of a platform-admin setting; an old pod
-- that still reads scope_approval_policy during the rollout fails closed
-- (required approvals) until it is replaced.
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_scope_approval_policy;
ALTER TABLE tenants RENAME COLUMN scope_approval_policy TO scan_approval_policy;
UPDATE tenants SET scan_approval_policy = CASE scan_approval_policy WHEN 'disabled' THEN 'off' ELSE NULL END
 WHERE scan_approval_policy IS NOT NULL;
ALTER TABLE tenants
    ADD CONSTRAINT chk_tenants_scan_approval_policy
    CHECK (scan_approval_policy IS NULL OR scan_approval_policy IN ('tenant_controlled', 'off', 'on', 'strict'));
COMMENT ON COLUMN tenants.scan_approval_policy IS
    'Platform administrator override of scan approval (RFC-072): tenant_controlled, off, on (at least on) or strict; NULL follows the platform default';

DELETE FROM platform_settings WHERE key = 'scope_approval_policy';
