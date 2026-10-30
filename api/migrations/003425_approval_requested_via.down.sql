ALTER TABLE finding_status_approvals
    DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_requested_via;
ALTER TABLE finding_status_approvals
    DROP COLUMN IF EXISTS requested_via;
