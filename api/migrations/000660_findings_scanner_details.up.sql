-- Scanner facts ingest parsed and dropped (research 17 R2): the rule family
-- (CTIS Finding.Category: Nessus / Tenable.sc plugin family, scanner rule
-- category), the scanner's exploit verdict, Tenable's VPR (display only, no
-- priority effect), the CVSS version of cvss_score, every CVE the scanner
-- named on the finding and the vendor patch publication date.
--
-- Safe on the live table: nullable columns and one constant default are
-- metadata-only changes (no rewrite). The CHECK constraints are NOT VALID, so
-- adding them does not scan the table; new and updated rows are checked.
-- Existing rows have NULLs only. Not fingerprint inputs.
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS family VARCHAR(255),
    ADD COLUMN IF NOT EXISTS exploit_available BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS vpr_score NUMERIC(3,1),
    ADD COLUMN IF NOT EXISTS cvss_version VARCHAR(8),
    ADD COLUMN IF NOT EXISTS cve_ids TEXT[],
    ADD COLUMN IF NOT EXISTS patch_published_at TIMESTAMPTZ;

ALTER TABLE findings ADD CONSTRAINT chk_findings_vpr_score CHECK (vpr_score > 0 AND vpr_score <= 10) NOT VALID;
ALTER TABLE findings ADD CONSTRAINT chk_findings_cve_ids_len CHECK (cardinality(cve_ids) <= 100) NOT VALID;

COMMENT ON COLUMN findings.family IS 'Rule family or category from the scanner (CTIS Finding.Category): Nessus/Tenable.sc plugin family, Semgrep/Checkov category. Not a fingerprint input.';
COMMENT ON COLUMN findings.exploit_available IS 'The scanner reported a public exploit (this tenant''s observation; the CVE catalog has its own flag).';
COMMENT ON COLUMN findings.vpr_score IS 'Tenable Vulnerability Priority Rating 0.1-10. Display only: not a prioritization input (research 17 A3).';
COMMENT ON COLUMN findings.cvss_version IS 'Version of cvss_score: 2.0, 3.0, 3.1, 3.x or 4.0.';
COMMENT ON COLUMN findings.cve_ids IS 'Every CVE the scanner named on this finding, primary first (cve_id is the primary). Multi-CVE network plugins are split into one finding per CVE (RFC-043 D3).';
COMMENT ON COLUMN findings.patch_published_at IS 'When the vendor published the fix (Nessus patch_publication_date, Tenable.sc patchPubDate).';
