-- The automations stay switched off (an automation that holds a removed type
-- cannot run either way), and the removed http_request headers are not
-- restored: they were credentials in plain config.
ALTER TABLE automations DROP CONSTRAINT IF EXISTS chk_automations_disabled_reason;
ALTER TABLE automations DROP COLUMN IF EXISTS disabled_reason;
