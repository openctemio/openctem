-- Validate chk_activity_type, re-added NOT VALID by sla_deadline_tighten_only.
-- VALIDATE scans finding_activities under SHARE UPDATE EXCLUSIVE: reads and
-- writes go on meanwhile.
ALTER TABLE finding_activities VALIDATE CONSTRAINT chk_activity_type;
