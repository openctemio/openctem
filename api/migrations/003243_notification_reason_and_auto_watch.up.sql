-- Why a person got a notification, how many events one notification stands
-- for, and whether they are watched automatically when they take part (RFC-120).
--
-- All three are metadata-only adds with constant defaults (no table rewrite).
-- coalesced_count: events of one item folded into one unread notification
-- within a short window. auto_watch: the person's switch for "watch what I take
-- part in" (default on); an explicit unsubscribe on an item always wins.

ALTER TABLE notifications ADD COLUMN IF NOT EXISTS reason varchar(16);
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS coalesced_count integer NOT NULL DEFAULT 1;
ALTER TABLE notification_preferences ADD COLUMN IF NOT EXISTS auto_watch boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN notifications.reason IS
    'Why the person got it: assigned, owner, watching, mentioned, approval, sla. NULL for notices that predate it.';

-- The lookup of an unread notification to fold a new event into.
CREATE INDEX IF NOT EXISTS idx_notifications_user_item_recent
    ON notifications (tenant_id, audience_id, notification_type, resource_id, created_at DESC)
    WHERE audience = 'user';
