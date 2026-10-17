-- Validates the CHECK constraints the previous migration added NOT VALID
-- (a SHARE UPDATE EXCLUSIVE lock: reads and writes continue).
ALTER TABLE finding_status_approvals VALIDATE CONSTRAINT chk_finding_status_approvals_tier;
ALTER TABLE finding_status_approvals VALIDATE CONSTRAINT chk_finding_status_approvals_required;
