ALTER TABLE scope_target_approvals
    DROP CONSTRAINT IF EXISTS chk_scope_target_approvals_self_reason,
    DROP CONSTRAINT IF EXISTS chk_scope_target_approvals_reason,
    DROP COLUMN IF EXISTS reason,
    DROP COLUMN IF EXISTS self_approved;

ALTER TABLE scope_targets DROP COLUMN IF EXISTS approval_reminded_at;
