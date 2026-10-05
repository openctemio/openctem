DROP INDEX IF EXISTS idx_findings_tenant_vex_status;
DROP INDEX IF EXISTS idx_findings_tenant_native_vuln_id;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_source_interop;
ALTER TABLE findings
    DROP COLUMN IF EXISTS vex_at,
    DROP COLUMN IF EXISTS vex_source,
    DROP COLUMN IF EXISTS vex_statement,
    DROP COLUMN IF EXISTS vex_justification,
    DROP COLUMN IF EXISTS vex_status,
    DROP COLUMN IF EXISTS location_key,
    DROP COLUMN IF EXISTS source_extra,
    DROP COLUMN IF EXISTS vulnerability_ids,
    DROP COLUMN IF EXISTS scores,
    DROP COLUMN IF EXISTS source_meta,
    DROP COLUMN IF EXISTS native_scheme,
    DROP COLUMN IF EXISTS native_vuln_id;
