-- Validate the constraints finding_severity_override added NOT VALID.
-- VALIDATE scans under SHARE UPDATE EXCLUSIVE: reads and writes go on
-- meanwhile. The new findings columns are NULL on every existing row.
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_source_severity;
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_severity_override;
ALTER TABLE findings VALIDATE CONSTRAINT fk_findings_severity_overridden_by;
ALTER TABLE finding_activities VALIDATE CONSTRAINT chk_activity_type;
