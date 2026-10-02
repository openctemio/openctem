-- Reverse 000207: drop the validation verdict columns + supporting objects.
DROP INDEX IF EXISTS idx_findings_downgraded;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_validation_outcome;
ALTER TABLE findings DROP COLUMN IF EXISTS downgraded_at;
ALTER TABLE findings DROP COLUMN IF EXISTS validation_outcome;
