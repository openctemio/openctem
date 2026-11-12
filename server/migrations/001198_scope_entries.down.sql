DELETE FROM role_permissions WHERE permission_id = 'attack_surface:scope:approve';
DELETE FROM permissions WHERE id = 'attack_surface:scope:approve';

DROP TABLE IF EXISTS scope_target_approvals;
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS uq_scope_targets_tenant_id;

DROP INDEX IF EXISTS idx_scope_targets_active;
CREATE INDEX idx_scope_targets_active ON scope_targets (tenant_id, status) WHERE status = 'active';

-- Rows only the new code writes cannot be kept under the old constraint:
-- pending and rejected entries never took effect; expired ones had ended.
DELETE FROM scope_targets WHERE status IN ('pending', 'rejected', 'expired');
ALTER TABLE scope_targets DROP CONSTRAINT chk_scope_target_status;
ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_target_status CHECK (status IN ('active', 'inactive'));

ALTER TABLE scope_targets
    DROP CONSTRAINT IF EXISTS chk_scope_target_max_tier,
    DROP CONSTRAINT IF EXISTS chk_scope_target_approvals,
    DROP CONSTRAINT IF EXISTS chk_scope_target_reason,
    DROP COLUMN expires_at,
    DROP COLUMN reason,
    DROP COLUMN max_tier,
    DROP COLUMN approvals_required,
    DROP COLUMN approved_at,
    DROP COLUMN rejected_by,
    DROP COLUMN rejected_at;
