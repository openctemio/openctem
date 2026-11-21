DROP TABLE IF EXISTS notification_group_items;
DROP TABLE IF EXISTS notification_groups;

ALTER TABLE integration_notification_extensions
    DROP CONSTRAINT IF EXISTS chk_integration_notification_group_window;
ALTER TABLE integration_notification_extensions
    DROP COLUMN IF EXISTS urgent_at_once,
    DROP COLUMN IF EXISTS group_window_minutes,
    DROP COLUMN IF EXISTS group_similar;
