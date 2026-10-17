-- Validates chk_findings_closure (added NOT VALID by finding_closure_trigger)
-- as its own step: SHARE UPDATE EXCLUSIVE, writes keep flowing.
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_closure;
