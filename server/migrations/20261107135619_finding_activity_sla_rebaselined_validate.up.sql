-- Validate chk_activity_type, re-added NOT VALID by finding_activity_sla_rebaselined.
-- VALIDATE scans under SHARE UPDATE EXCLUSIVE: reads and writes go on meanwhile.
ALTER TABLE finding_activities VALIDATE CONSTRAINT chk_activity_type;
