-- Add 'expired' status to finding_status_approvals
-- Used by the background approval expiration controller to mark
-- approved risk acceptances that have passed their expires_at date.

-- Drop and recreate the CHECK constraint to include 'expired'
ALTER TABLE finding_status_approvals
    DROP CONSTRAINT IF EXISTS finding_status_approvals_status_check;

ALTER TABLE finding_status_approvals
    ADD CONSTRAINT finding_status_approvals_status_check
    CHECK (status IN ('pending', 'approved', 'rejected', 'canceled', 'expired'));

-- Index for the expiration controller query:
-- SELECT ... WHERE status = 'approved' AND expires_at IS NOT NULL AND expires_at < NOW()
CREATE INDEX IF NOT EXISTS idx_approvals_expired_lookup
    ON finding_status_approvals (expires_at)
    WHERE status = 'approved' AND expires_at IS NOT NULL;
