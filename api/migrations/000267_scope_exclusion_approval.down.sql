DROP INDEX IF EXISTS idx_scope_exclusions_tenant_pending;

-- Pending and rejected exclusions were never in effect; keep them out of
-- effect under the old status set.
UPDATE scope_exclusions SET status = 'inactive' WHERE status IN ('pending', 'rejected');

ALTER TABLE scope_exclusions ALTER COLUMN status SET DEFAULT 'active';
ALTER TABLE scope_exclusions DROP CONSTRAINT IF EXISTS chk_scope_exclusion_status;
ALTER TABLE scope_exclusions ADD CONSTRAINT chk_scope_exclusion_status
    CHECK (status IN ('active', 'inactive', 'expired'));

ALTER TABLE scope_exclusions DROP COLUMN IF EXISTS rejected_at;
ALTER TABLE scope_exclusions DROP COLUMN IF EXISTS rejected_by;

DELETE FROM role_permissions WHERE permission_id = 'attack_surface:scope:exclusions:approve';
DELETE FROM permissions WHERE id = 'attack_surface:scope:exclusions:approve';
