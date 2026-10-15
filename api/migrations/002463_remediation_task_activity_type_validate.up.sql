-- Validate chk_activity_type, re-added NOT VALID by
-- remediation_task_activity_type. VALIDATE scans finding_activities under
-- SHARE UPDATE EXCLUSIVE: reads and writes go on meanwhile.
ALTER TABLE finding_activities VALIDATE CONSTRAINT chk_activity_type;
