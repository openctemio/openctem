-- Enable the new "finding_priority_escalated" notification event type for
-- integrations that already exist.
--
-- Why a migration is required for this to work at all:
-- integration_notification_extensions.enabled_event_types is an opt-in
-- whitelist. NotificationExtension.ShouldNotifyEventType returns true only
-- when the list is EMPTY (legacy "allow all") or the event type is a literal
-- member of it. Since migration 000045 the column defaults to
-- '["security_alert","new_finding","new_exposure"]' and NULLs are backfilled
-- and COALESCE'd to the same value, so in practice no row has an empty list.
--
-- That means an outbox entry carrying a brand-new event type is enqueued
-- successfully, matches zero integrations at delivery time, is marked
-- completed by the "no matching integrations" branch, archived, and deleted —
-- silently delivering nothing. Adding the constant on the Go side alone would
-- have shipped exactly that: code that runs and can never have an effect.
--
-- Appending it here (idempotent, only where it is not already present) makes
-- priority escalations actually reach the channels a tenant has already
-- connected. Tenants who do not want it can deselect it in the UI, where the
-- new type is now listed via integration.AllEventTypes().
-- The jsonb_array_length(...) > 0 guard is load-bearing: an EMPTY array is the
-- legacy "allow all events" state. Appending to it would flip that row from
-- "delivers everything" to "delivers escalations and nothing else", silencing
-- every other notification for that tenant — a far worse failure than the one
-- being fixed. Empty stays empty and keeps allowing everything, escalations
-- included.
UPDATE integration_notification_extensions
SET enabled_event_types = enabled_event_types || '["finding_priority_escalated"]'::jsonb
WHERE enabled_event_types IS NOT NULL
  AND jsonb_typeof(enabled_event_types) = 'array'
  AND jsonb_array_length(enabled_event_types) > 0
  AND NOT (enabled_event_types @> '["finding_priority_escalated"]'::jsonb);
