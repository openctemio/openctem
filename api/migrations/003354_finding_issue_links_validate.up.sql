-- Validate chk_activity_type, re-added NOT VALID by finding_issue_links.
-- VALIDATE scans under SHARE UPDATE EXCLUSIVE: reads and writes go on meanwhile.
ALTER TABLE finding_activities VALIDATE CONSTRAINT chk_activity_type;
