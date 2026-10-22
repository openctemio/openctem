-- Per-channel delivery state of a notification outbox entry
-- (docs/architecture/notification-system.md, "Delivery per channel").
--
-- One element per channel the event goes to, each with its own attempts,
-- backoff and outcome, so a failed channel is retried even when another one
-- succeeded, and a channel that got the event is never sent it again.
-- An entry processed before this column existed has '[]' and resolves its
-- channels on its next pass, as a new entry does.
-- ADD COLUMN with a constant default is a catalog-only change: no table
-- rewrite, safe on a populated outbox.

ALTER TABLE notification_outbox
    ADD COLUMN IF NOT EXISTS deliveries jsonb NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN notification_outbox.deliveries IS
    'Per-channel delivery state: [{integration_id, name, provider, status, attempts, next_attempt_at, last_attempt_at, last_error, message_id}]';
