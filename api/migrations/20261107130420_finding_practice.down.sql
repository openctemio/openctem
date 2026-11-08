ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_practice;
ALTER TABLE findings DROP COLUMN IF EXISTS practice_reason, DROP COLUMN IF EXISTS practice;
