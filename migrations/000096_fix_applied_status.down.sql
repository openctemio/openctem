-- Revert fix_applied status changes

-- Remove permissions
DELETE FROM role_permissions WHERE permission_id IN ('findings:fix_apply', 'findings:verify');
DELETE FROM permissions WHERE id IN ('findings:fix_apply', 'findings:verify');

-- Remove indexes
DROP INDEX IF EXISTS idx_findings_fix_applied;
DROP INDEX IF EXISTS idx_assets_tenant_owner;
DROP INDEX IF EXISTS idx_findings_tenant_cve;

-- Revert legacy resolution_method
UPDATE findings SET resolution_method = NULL WHERE resolution_method = 'legacy';

-- Remove column
ALTER TABLE findings DROP COLUMN IF EXISTS resolution_method;

-- Revert fix_applied findings back to in_progress
UPDATE findings SET status = 'in_progress' WHERE status = 'fix_applied';
