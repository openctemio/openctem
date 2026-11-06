-- A linked ticket (a Jira issue moved to "Won't Do") requests a risk
-- acceptance or a false positive (actor 'ticket', no person) instead of
-- setting it: a person with the approve permission decides (four-eyes).
ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_actor;
ALTER TABLE finding_status_approvals
    ADD CONSTRAINT chk_finding_status_approvals_actor
    CHECK (requested_by_actor IS NULL OR (requested_by_actor IN ('ai_triage', 'vex', 'ticket') AND requested_by IS NULL)) NOT VALID;
