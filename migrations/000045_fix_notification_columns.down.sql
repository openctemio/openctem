-- Revert notification extension columns: JSONB → TEXT[]
ALTER TABLE integration_notification_extensions
    ALTER COLUMN enabled_severities TYPE TEXT[] USING
        CASE
            WHEN enabled_severities IS NULL THEN '{}'::text[]
            ELSE ARRAY(SELECT jsonb_array_elements_text(enabled_severities))
        END,
    ALTER COLUMN enabled_event_types TYPE TEXT[] USING
        CASE
            WHEN enabled_event_types IS NULL THEN '{}'::text[]
            ELSE ARRAY(SELECT jsonb_array_elements_text(enabled_event_types))
        END;

ALTER TABLE integration_notification_extensions
    ALTER COLUMN enabled_severities SET DEFAULT '{}',
    ALTER COLUMN enabled_event_types SET DEFAULT '{}';
