UPDATE finding_status_approvals SET status = 'canceled' WHERE requested_by_actor = 'ticket' AND status = 'pending';
ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_actor;
ALTER TABLE finding_status_approvals
    ADD CONSTRAINT chk_finding_status_approvals_actor
    CHECK (requested_by_actor IS NULL OR (requested_by_actor IN ('ai_triage', 'vex') AND requested_by IS NULL)) NOT VALID;
