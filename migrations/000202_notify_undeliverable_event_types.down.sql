-- Remove the event types added by 000202 from every integration's opt-in
-- whitelist. The `- 'key'` operator on a jsonb array removes all matching
-- elements and is a no-op when the element is absent, so this is safe to run
-- against rows that never received the backfill.
--
-- Rows whose array is empty were skipped by the up migration and are untouched
-- here, keeping the legacy "allow all" state intact in both directions.
UPDATE integration_notification_extensions
SET enabled_event_types = enabled_event_types
    - 'sla_breach'
    - 'finding_assigned'
    - 'workflow_notification'
    - 'approval_requested'
WHERE enabled_event_types IS NOT NULL
  AND jsonb_typeof(enabled_event_types) = 'array'
  AND (enabled_event_types @> '["sla_breach"]'::jsonb
    OR enabled_event_types @> '["finding_assigned"]'::jsonb
    OR enabled_event_types @> '["workflow_notification"]'::jsonb
    OR enabled_event_types @> '["approval_requested"]'::jsonb);
