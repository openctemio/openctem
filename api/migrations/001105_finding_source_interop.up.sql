-- Source interoperability data of a finding (CTIS 1.4, spec section 4.10):
-- what the source scanner or importer knew about the finding in its own
-- terms, next to the normalized finding.
--
--   native_vuln_id     the source's id of the check (plugin ID, QID, rule id)
--   native_scheme      vocabulary of the native values (nessus, qualys, ...)
--   source_meta        native identity, source lifecycle, solution metadata
--   scores             every score with its system, version, source and date
--   vulnerability_ids  typed vulnerability ids (cve, ghsa, osv, vendor)
--   source_extra       unmapped source fields (strings, at most 32 KiB)
--   location_key       normalized location on the asset (ctis.LocationKey)
--   vex_*              the latest VEX statement about the finding
--
-- Every value is producer-supplied and untrusted (RFC-040). The application
-- bounds it before writing (vulnerability.SanitizeInteropData); the CHECK
-- constraints are the backstop. Only the finding detail view reads these
-- columns; lists, exports, tickets and notifications do not.
--
-- Safe on the live table: nullable columns without defaults are
-- metadata-only (no rewrite), and the CHECK constraints are NOT VALID, so
-- adding them scans nothing (every existing row is NULL in these columns).
-- The partial indexes cover no row yet.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS native_vuln_id text,
    ADD COLUMN IF NOT EXISTS native_scheme text,
    ADD COLUMN IF NOT EXISTS source_meta jsonb,
    ADD COLUMN IF NOT EXISTS scores jsonb,
    ADD COLUMN IF NOT EXISTS vulnerability_ids jsonb,
    ADD COLUMN IF NOT EXISTS source_extra jsonb,
    ADD COLUMN IF NOT EXISTS location_key text,
    ADD COLUMN IF NOT EXISTS vex_status text,
    ADD COLUMN IF NOT EXISTS vex_justification text,
    ADD COLUMN IF NOT EXISTS vex_statement text,
    ADD COLUMN IF NOT EXISTS vex_source text,
    ADD COLUMN IF NOT EXISTS vex_at timestamptz;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_source_interop;
ALTER TABLE findings ADD CONSTRAINT chk_findings_source_interop CHECK (
    (native_vuln_id IS NULL OR length(native_vuln_id) <= 256)
    AND (native_scheme IS NULL OR length(native_scheme) <= 64)
    AND (source_meta IS NULL OR (jsonb_typeof(source_meta) = 'object' AND octet_length(source_meta::text) <= 16384))
    AND (scores IS NULL OR (jsonb_typeof(scores) = 'array' AND jsonb_array_length(scores) <= 32))
    AND (vulnerability_ids IS NULL OR (jsonb_typeof(vulnerability_ids) = 'array' AND jsonb_array_length(vulnerability_ids) <= 64))
    AND (source_extra IS NULL OR (jsonb_typeof(source_extra) = 'object' AND octet_length(source_extra::text) <= 49152))
    AND (location_key IS NULL OR length(location_key) <= 512)
    AND (vex_status IS NULL OR vex_status IN ('not_affected', 'affected', 'fixed', 'under_investigation'))
    AND (vex_justification IS NULL OR vex_justification IN (
        'component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path',
        'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist'))
    AND (vex_statement IS NULL OR length(vex_statement) <= 4096)
    AND (vex_source IS NULL OR length(vex_source) <= 512)
) NOT VALID;

-- Correlation by the source's own check id within a tenant (the same
-- plugin / QID across assets).
CREATE INDEX IF NOT EXISTS idx_findings_tenant_native_vuln_id
    ON findings (tenant_id, native_scheme, native_vuln_id) WHERE native_vuln_id IS NOT NULL;

-- Findings a VEX statement covers, for review.
CREATE INDEX IF NOT EXISTS idx_findings_tenant_vex_status
    ON findings (tenant_id, vex_status) WHERE vex_status IS NOT NULL;

COMMENT ON COLUMN findings.native_vuln_id IS 'Source id of the check (plugin ID, QID, rule id); CTIS native.vuln_id. Untrusted.';
COMMENT ON COLUMN findings.native_scheme IS 'Vocabulary of the native values (CTIS native.scheme).';
COMMENT ON COLUMN findings.source_meta IS 'Native identity, source lifecycle and solution metadata of the latest sighting (CTIS 1.4). Untrusted; detail view only.';
COMMENT ON COLUMN findings.scores IS 'Every score of the latest sighting with system, version, vector, value, source and date (CTIS scores + legacy cvss/epss/vpr).';
COMMENT ON COLUMN findings.vulnerability_ids IS 'Typed vulnerability ids of the latest sighting (cve, ghsa, osv, vendor).';
COMMENT ON COLUMN findings.source_extra IS 'Unmapped source fields of the latest sighting, strings, bounded. Untrusted; detail view only.';
COMMENT ON COLUMN findings.location_key IS 'Normalized location on the asset (ctis.LocationKey), derived by the server.';
COMMENT ON COLUMN findings.vex_status IS 'Latest VEX status reported for the finding.';
COMMENT ON COLUMN findings.vex_justification IS 'VEX not_affected justification (CSAF / OpenVEX).';
COMMENT ON COLUMN findings.vex_statement IS 'VEX impact or action statement. Untrusted plain text.';
COMMENT ON COLUMN findings.vex_source IS 'Who made the VEX statement (document id or URL, vendor, team), as reported.';
COMMENT ON COLUMN findings.vex_at IS 'When the VEX statement was made (or recorded, when the source gave no date).';
