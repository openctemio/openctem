-- Validates the closure CHECK added NOT VALID by finding_closure_reason, once
-- every row was backfilled (a separate step so the check scan holds only a
-- SHARE UPDATE EXCLUSIVE lock).
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_closure;
