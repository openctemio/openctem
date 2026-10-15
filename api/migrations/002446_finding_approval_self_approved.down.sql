ALTER TABLE finding_status_approvals
    DROP COLUMN IF EXISTS self_approval_reason,
    DROP COLUMN IF EXISTS self_approved;
