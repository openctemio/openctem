-- include_details was kept in sync until now only by the backfill: restore it
-- from the level (anything above minimal sent details).
UPDATE integration_notification_extensions
SET include_details = (detail_level <> 'minimal');

ALTER TABLE integration_notification_extensions
    DROP CONSTRAINT IF EXISTS chk_notification_detail_level;
ALTER TABLE integration_notification_extensions
    DROP COLUMN IF EXISTS detail_level;
