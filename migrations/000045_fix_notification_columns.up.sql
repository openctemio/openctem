-- Fix notification extension columns: TEXT[] → JSONB
-- The code uses json.Marshal/Unmarshal but columns were defined as TEXT[]
-- This causes COALESCE type mismatch errors

-- Drop defaults first (they can't be auto-cast)
ALTER TABLE integration_notification_extensions
    ALTER COLUMN enabled_severities DROP DEFAULT,
    ALTER COLUMN enabled_event_types DROP DEFAULT;

-- Change column types
ALTER TABLE integration_notification_extensions
    ALTER COLUMN enabled_severities TYPE JSONB USING
        CASE
            WHEN enabled_severities IS NULL THEN '["critical", "high"]'::jsonb
            ELSE to_jsonb(enabled_severities)
        END,
    ALTER COLUMN enabled_event_types TYPE JSONB USING
        CASE
            WHEN enabled_event_types IS NULL THEN '["security_alert", "new_finding", "new_exposure"]'::jsonb
            ELSE to_jsonb(enabled_event_types)
        END;

-- Set new JSONB defaults
ALTER TABLE integration_notification_extensions
    ALTER COLUMN enabled_severities SET DEFAULT '["critical", "high"]'::jsonb,
    ALTER COLUMN enabled_event_types SET DEFAULT '["security_alert", "new_finding", "new_exposure"]'::jsonb;
