-- Validates the constraints added NOT VALID by finding_status_dimensions, as
-- separate steps (SHARE UPDATE EXCLUSIVE, no write lock).
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_status;
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_observation_state;
