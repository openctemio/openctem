-- Scope exclusions need a second person's approval before they take effect.
--
-- An exclusion suppresses scanning of whatever it matches. Until now a new
-- exclusion was created 'active' and applied to the next scan immediately, and
-- approving it was gated on attack_surface:scope:write, which every member
-- holds. Now:
--   * a new exclusion is created 'pending' and is not applied anywhere;
--   * approving or rejecting it needs attack_surface:scope:exclusions:approve,
--     granted to the owner and admin system roles (custom roles do not get it;
--     a tenant grants it deliberately);
--   * the requester still cannot approve their own exclusion;
--   * a rejected exclusion ('rejected') never takes effect.
--
-- Existing rows: every exclusion that is 'active' today stays in effect. Those
-- that were never approved are marked approved here (approved_by
-- 'system:pre-approval-grandfathered', approved_at = created_at), because the
-- application now applies only approved exclusions. Inactive and expired rows
-- are left as they are; turning one back on now needs an approval.

INSERT INTO permissions (id, module_id, name, description) VALUES
    ('attack_surface:scope:exclusions:approve', 'scope', 'Approve Scope Exclusions', 'Approve or reject a pending scope exclusion (it suppresses scanning)')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, 'attack_surface:scope:exclusions:approve'
FROM (VALUES
    ('00000000-0000-0000-0000-000000000001'::uuid), -- owner
    ('00000000-0000-0000-0000-000000000002'::uuid)  -- admin
) AS r(role_id)
ON CONFLICT DO NOTHING;

ALTER TABLE scope_exclusions ADD COLUMN IF NOT EXISTS rejected_by VARCHAR(200);
ALTER TABLE scope_exclusions ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMPTZ;

ALTER TABLE scope_exclusions DROP CONSTRAINT IF EXISTS chk_scope_exclusion_status;
ALTER TABLE scope_exclusions ADD CONSTRAINT chk_scope_exclusion_status
    CHECK (status IN ('active', 'inactive', 'expired', 'pending', 'rejected'));

-- A row inserted without a status (no application path does) must not be live.
ALTER TABLE scope_exclusions ALTER COLUMN status SET DEFAULT 'pending';

UPDATE scope_exclusions
SET approved_by = COALESCE(NULLIF(approved_by, ''), 'system:pre-approval-grandfathered'),
    approved_at = COALESCE(approved_at, created_at, NOW())
WHERE status = 'active'
  AND (approved_at IS NULL OR approved_by IS NULL OR approved_by = '');

-- Pending exclusions are listed for reviewers per tenant.
CREATE INDEX IF NOT EXISTS idx_scope_exclusions_tenant_pending
    ON scope_exclusions (tenant_id, created_at DESC) WHERE status = 'pending';
