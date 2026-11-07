-- Notification channels: a detail level (minimal, standard, full) replaces the
-- include_details switch. Design: docs/architecture/notification-system.md,
-- "Detail levels". Existing channels keep exactly what they send today:
-- details on becomes full, details off becomes minimal. A new channel is
-- standard. include_details is no longer read or written; a later migration
-- drops it.
ALTER TABLE integration_notification_extensions
    ADD COLUMN IF NOT EXISTS detail_level VARCHAR(16) NOT NULL DEFAULT 'standard';

UPDATE integration_notification_extensions
SET detail_level = CASE WHEN include_details IS TRUE THEN 'full' ELSE 'minimal' END;

ALTER TABLE integration_notification_extensions
    DROP CONSTRAINT IF EXISTS chk_notification_detail_level;
ALTER TABLE integration_notification_extensions
    ADD CONSTRAINT chk_notification_detail_level CHECK (detail_level IN ('minimal', 'standard', 'full'));
