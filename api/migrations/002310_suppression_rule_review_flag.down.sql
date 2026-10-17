ALTER TABLE suppression_rules ALTER COLUMN expires_at DROP DEFAULT;
ALTER TABLE suppression_rules DROP COLUMN IF EXISTS review_reason;
ALTER TABLE suppression_rules DROP COLUMN IF EXISTS review_flagged_at;
