-- A VEX not_affected statement in a scan report requests a false positive
-- (actor 'vex', no person) instead of setting it: a false positive needs
-- four-eyes, so a person with the approve permission decides.
ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_actor;
ALTER TABLE finding_status_approvals
    ADD CONSTRAINT chk_finding_status_approvals_actor
    CHECK (requested_by_actor IS NULL OR (requested_by_actor IN ('ai_triage', 'vex') AND requested_by IS NULL)) NOT VALID;
