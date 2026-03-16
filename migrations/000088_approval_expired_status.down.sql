-- Revert 'expired' status from finding_status_approvals
DROP INDEX IF EXISTS idx_approvals_expired_lookup;

ALTER TABLE finding_status_approvals
    DROP CONSTRAINT IF EXISTS finding_status_approvals_status_check;

ALTER TABLE finding_status_approvals
    ADD CONSTRAINT finding_status_approvals_status_check
    CHECK (status IN ('pending', 'approved', 'rejected', 'canceled'));
