-- Validate chk_activity_type, which finding_locations re-added NOT VALID
-- with the location_changed activity. VALIDATE scans under SHARE UPDATE
-- EXCLUSIVE: reads and writes go on meanwhile, and every existing row
-- already satisfies the wider list.
ALTER TABLE finding_activities VALIDATE CONSTRAINT chk_activity_type;
