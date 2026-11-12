-- When the approvers of a pending finding request were last reminded; a
-- reminder is allowed at most once an hour per request (checked atomically
-- by FindingApprovalRepository.MarkReminded).
--
-- Live impact: a nullable column (no rewrite) on a small table.

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS reminded_at timestamptz;

COMMENT ON COLUMN finding_status_approvals.reminded_at IS
    'Last reminder sent to the approvers of a pending request (rate limit: one per hour)';
