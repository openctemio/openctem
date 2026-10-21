DROP INDEX IF EXISTS idx_notifications_user_item_recent;
ALTER TABLE notification_preferences DROP COLUMN IF EXISTS auto_watch;
ALTER TABLE notifications DROP COLUMN IF EXISTS coalesced_count;
ALTER TABLE notifications DROP COLUMN IF EXISTS reason;
