-- Scanner output (Nessus / Tenable plugin output, any tool's evidence text)
-- and both CVSS vectors, research 24 P0-2, owner decision C9.
--
-- scanner_output is attacker-influenced text: a scanned host controls the
-- banners, HTTP bodies and file contents a plugin prints, and a hostile
-- sensor can send anything (RFC-040). It is stored as plain text, capped at
-- 64 KiB, read only by the finding detail view, never by lists, exports,
-- tickets or notifications. A retention job clears it 365 days after the
-- finding was closed (C9).
--
-- Safe on the live table: nullable columns without defaults are
-- metadata-only (no rewrite). The CHECK constraints are NOT VALID, so adding
-- them does not scan the table; new and updated rows are checked, and the
-- existing rows only have NULLs. The partial index covers no row yet, so
-- building it is one scan with nothing to insert.
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS scanner_output TEXT,
    ADD COLUMN IF NOT EXISTS scanner_output_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cvss_v2_vector VARCHAR(200),
    ADD COLUMN IF NOT EXISTS cvss_v3_vector VARCHAR(200);

ALTER TABLE findings ADD CONSTRAINT chk_findings_scanner_output_len
    CHECK (octet_length(scanner_output) <= 65536) NOT VALID;

COMMENT ON COLUMN findings.scanner_output IS 'Scanner output for this finding (plugin output, evidence text) from its latest sighting. Untrusted text, at most 64 KiB; detail view only; cleared 365 days after close.';
COMMENT ON COLUMN findings.scanner_output_at IS 'When scanner_output was last written (the sighting it came from).';
COMMENT ON COLUMN findings.cvss_v2_vector IS 'CVSS v2 vector reported by the scanner.';
COMMENT ON COLUMN findings.cvss_v3_vector IS 'CVSS v3.x vector reported by the scanner.';

-- The retention sweep: closed findings that still hold output.
CREATE INDEX IF NOT EXISTS idx_findings_scanner_output_retention
    ON findings (resolved_at) WHERE scanner_output IS NOT NULL;
