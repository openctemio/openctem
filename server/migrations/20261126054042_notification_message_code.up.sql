-- A notification's text as a stable message code plus typed values, so the
-- web shows it in the reader's language (docs/architecture/notification-system.md).
-- title and body keep the English text: older rows, e-mail, chat and webhook
-- deliveries still read them, and the web falls back to them for a code it
-- does not know.
--
-- Both columns are nullable adds without a default (metadata only, no table
-- rewrite). The checks are added NOT VALID and validated afterwards, so the
-- add takes no long lock on a populated table; every existing row is NULL.

ALTER TABLE notifications ADD COLUMN IF NOT EXISTS message_code varchar(96);
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS message_params jsonb;

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS chk_notification_message_code;
ALTER TABLE notifications ADD CONSTRAINT chk_notification_message_code
    CHECK (message_code IS NULL OR message_code ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$') NOT VALID;
ALTER TABLE notifications VALIDATE CONSTRAINT chk_notification_message_code;

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS chk_notification_message_params;
ALTER TABLE notifications ADD CONSTRAINT chk_notification_message_params
    CHECK (message_params IS NULL OR (jsonb_typeof(message_params) = 'object' AND pg_column_size(message_params) <= 16384)) NOT VALID;
ALTER TABLE notifications VALIDATE CONSTRAINT chk_notification_message_params;

COMMENT ON COLUMN notifications.message_code IS
    'Stable code of the notice text (for example coverage.gap); the web renders it from its catalogs. NULL for notices that predate it: title and body are shown.';
COMMENT ON COLUMN notifications.message_params IS
    'Typed values of message_code (counts, names, capability keys). Display text only, never instructions or markup.';
