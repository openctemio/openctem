ALTER TABLE notifications DROP CONSTRAINT IF EXISTS chk_notification_message_params;
ALTER TABLE notifications DROP CONSTRAINT IF EXISTS chk_notification_message_code;
ALTER TABLE notifications DROP COLUMN IF EXISTS message_params;
ALTER TABLE notifications DROP COLUMN IF EXISTS message_code;
