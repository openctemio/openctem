DROP INDEX IF EXISTS idx_findings_scanner_output_retention;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_scanner_output_len;
ALTER TABLE findings
    DROP COLUMN IF EXISTS cvss_v3_vector,
    DROP COLUMN IF EXISTS cvss_v2_vector,
    DROP COLUMN IF EXISTS scanner_output_at,
    DROP COLUMN IF EXISTS scanner_output;
