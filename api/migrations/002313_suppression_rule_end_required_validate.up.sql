-- Validates chk_suppression_rules_expires_at_set on the existing rows (the
-- backfill gave every rule an end). SHARE UPDATE EXCLUSIVE: reads and writes
-- go on.
ALTER TABLE suppression_rules VALIDATE CONSTRAINT chk_suppression_rules_expires_at_set;
