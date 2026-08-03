-- Remove the finding_priority_escalated event type from every integration's
-- opt-in whitelist.
UPDATE integration_notification_extensions
SET enabled_event_types = enabled_event_types - 'finding_priority_escalated'
WHERE enabled_event_types IS NOT NULL
  AND jsonb_typeof(enabled_event_types) = 'array'
  AND enabled_event_types @> '["finding_priority_escalated"]'::jsonb;
