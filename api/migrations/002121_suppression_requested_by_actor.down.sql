ALTER TABLE suppression_rules DROP CONSTRAINT IF EXISTS chk_suppression_rules_requested_by_actor;
ALTER TABLE suppression_rules DROP COLUMN IF EXISTS requested_by_actor;
