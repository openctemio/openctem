-- =============================================================================
-- Migration 020: Notifications (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_notification_outbox_updated_at ON notification_outbox;

DROP TABLE IF EXISTS notification_events;
DROP TABLE IF EXISTS notification_outbox;
DROP TABLE IF EXISTS event_types;
