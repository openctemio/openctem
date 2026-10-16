-- Validates the findings sub-status foreign key added NOT VALID: every value
-- is NULL until an organization uses sub-statuses, so the scan finds nothing
-- to check, and VALIDATE takes only a SHARE UPDATE EXCLUSIVE lock (writes go on).
ALTER TABLE findings VALIDATE CONSTRAINT fk_findings_sub_status;
