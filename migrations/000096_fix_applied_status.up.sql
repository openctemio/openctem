-- 000096: Closed-Loop Finding Lifecycle — fix_applied status
--
-- Adds:
-- 1. resolution_method column on findings (track HOW a finding was resolved)
-- 2. Index on findings(tenant_id, cve_id) — CRITICAL for GROUP BY queries
-- 3. Index on assets(tenant_id, owner_id) — for GROUP BY owner
-- 4. Partial index on findings(status='fix_applied') — for pending verification queries
-- 5. Backward compat: mark existing resolved findings as 'legacy'
-- 6. Permissions: findings:fix_apply, findings:verify

-- 1. resolution_method: tracks how a finding was resolved
-- Values: NULL (not resolved), 'legacy', 'scan_verified', 'security_reviewed', 'admin_direct'
-- System-only field — NOT settable via API input
ALTER TABLE findings ADD COLUMN IF NOT EXISTS resolution_method VARCHAR(30);

-- 2. Backward compatibility: existing resolved findings get 'legacy' method
UPDATE findings SET resolution_method = 'legacy'
    WHERE status = 'resolved' AND resolution_method IS NULL;

-- 3. Index for GROUP BY cve_id (currently MISSING — causes full table scan)
-- Note: not using CONCURRENTLY — golang-migrate runs in transaction
CREATE INDEX IF NOT EXISTS idx_findings_tenant_cve
    ON findings(tenant_id, cve_id)
    WHERE cve_id IS NOT NULL;

-- 4. Index for GROUP BY owner_id (JOIN findings→assets→users)
CREATE INDEX IF NOT EXISTS idx_assets_tenant_owner
    ON assets(tenant_id, owner_id)
    WHERE owner_id IS NOT NULL;

-- 5. Partial index for fix_applied findings (pending verification queries)
CREATE INDEX IF NOT EXISTS idx_findings_fix_applied
    ON findings(tenant_id, updated_at DESC)
    WHERE status = 'fix_applied';

-- 6. Permissions
INSERT INTO permissions (id, module_id, name, description) VALUES
    ('findings:fix_apply', 'findings', 'Mark Fix Applied', 'Mark findings as fix applied (dev/owner action)'),
    ('findings:verify', 'findings', 'Verify Findings', 'Verify and resolve fix-applied findings (security action)')
ON CONFLICT (id) DO NOTHING;

-- Owner + Admin get both permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.slug IN ('owner', 'admin')
  AND p.id IN ('findings:fix_apply', 'findings:verify')
ON CONFLICT DO NOTHING;

-- Member gets fix_apply only (can mark fixed, cannot resolve)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.slug = 'member'
  AND p.id = 'findings:fix_apply'
ON CONFLICT DO NOTHING;
