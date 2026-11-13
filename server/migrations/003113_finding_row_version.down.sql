DROP TRIGGER IF EXISTS trg_findings_row_version ON findings;
DROP FUNCTION IF EXISTS findings_bump_row_version();
ALTER TABLE findings DROP COLUMN IF EXISTS row_version;
