DROP INDEX IF EXISTS idx_findings_created_by;
ALTER TABLE findings DROP COLUMN IF EXISTS created_by;
