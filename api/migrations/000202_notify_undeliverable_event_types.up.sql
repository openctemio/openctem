-- Enable the notification event types that production code has been emitting
-- all along but that no integration could be configured to receive.
--
-- Why a migration is required for this to work at all:
-- integration_notification_extensions.enabled_event_types is an opt-in
-- whitelist. NotificationExtension.ShouldNotifyEventType returns true only when
-- the list is EMPTY (legacy "allow all") or the event type is a literal member
-- of it. Since migration 000045 the column defaults to
-- '["security_alert","new_finding","new_exposure"]' and NULLs are backfilled and
-- COALESCE'd to the same value, so in practice no row has an empty list.
--
-- That means an outbox entry carrying one of these event types was enqueued
-- successfully, matched zero integrations at delivery time, was marked completed
-- by the "no matching integrations" branch, archived, and deleted — silently
-- delivering nothing. sla_breach is the one that mattered: an SLA breach that
-- notified nobody.
--
-- Only the four types that are also being added to DefaultEnabledEventTypes()
-- are backfilled here. approval_approved and approval_rejected are registered on
-- the Go side (so they are selectable) but stay opt-in: they are FYI traffic for
-- the requester and appending them would start broadcasting every approval
-- outcome to every connected channel without anyone asking.
--
-- The jsonb_array_length(...) > 0 guard is load-bearing: an EMPTY array is the
-- legacy "allow all events" state. Appending to it would flip that row from
-- "delivers everything" to "delivers only what was appended", silencing every
-- other notification for that tenant — a far worse failure than the one being
-- fixed. Empty stays empty and keeps allowing everything, these types included.
--
-- The @> guard makes this idempotent and preserves a deliberate operator choice:
-- a tenant who already selected one of these types is not given a duplicate.
UPDATE integration_notification_extensions
SET enabled_event_types = enabled_event_types || '["sla_breach"]'::jsonb
WHERE enabled_event_types IS NOT NULL
  AND jsonb_typeof(enabled_event_types) = 'array'
  AND jsonb_array_length(enabled_event_types) > 0
  AND NOT (enabled_event_types @> '["sla_breach"]'::jsonb);

UPDATE integration_notification_extensions
SET enabled_event_types = enabled_event_types || '["finding_assigned"]'::jsonb
WHERE enabled_event_types IS NOT NULL
  AND jsonb_typeof(enabled_event_types) = 'array'
  AND jsonb_array_length(enabled_event_types) > 0
  AND NOT (enabled_event_types @> '["finding_assigned"]'::jsonb);

UPDATE integration_notification_extensions
SET enabled_event_types = enabled_event_types || '["workflow_notification"]'::jsonb
WHERE enabled_event_types IS NOT NULL
  AND jsonb_typeof(enabled_event_types) = 'array'
  AND jsonb_array_length(enabled_event_types) > 0
  AND NOT (enabled_event_types @> '["workflow_notification"]'::jsonb);

UPDATE integration_notification_extensions
SET enabled_event_types = enabled_event_types || '["approval_requested"]'::jsonb
WHERE enabled_event_types IS NOT NULL
  AND jsonb_typeof(enabled_event_types) = 'array'
  AND jsonb_array_length(enabled_event_types) > 0
  AND NOT (enabled_event_types @> '["approval_requested"]'::jsonb);
