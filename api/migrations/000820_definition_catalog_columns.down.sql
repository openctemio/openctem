-- Back to the CVE-only catalog. Definitions that have no CVE cannot exist in
-- that schema (cve_id NOT NULL), so they are deleted first: tenant-scoped
-- definitions and any non-CVE global one. Findings that pointed at them keep
-- their row; findings.vulnerability_id is ON DELETE SET NULL.
DROP POLICY IF EXISTS vulnerabilities_scope_isolation ON vulnerabilities;

DROP TRIGGER IF EXISTS trigger_vulnerabilities_definition_compat ON vulnerabilities;
DROP FUNCTION IF EXISTS vulnerabilities_definition_compat();

DELETE FROM vulnerabilities WHERE cve_id IS NULL OR tenant_id IS NOT NULL;

ALTER TABLE vulnerabilities
    DROP CONSTRAINT IF EXISTS fk_vulnerabilities_tenant,
    DROP CONSTRAINT IF EXISTS chk_vuln_kind,
    DROP CONSTRAINT IF EXISTS chk_vuln_namespace,
    DROP CONSTRAINT IF EXISTS chk_vuln_lifecycle,
    DROP CONSTRAINT IF EXISTS chk_vuln_origin,
    DROP CONSTRAINT IF EXISTS chk_vuln_scope_tenant,
    DROP CONSTRAINT IF EXISTS chk_vuln_origin_scope,
    DROP CONSTRAINT IF EXISTS chk_vuln_merged,
    DROP CONSTRAINT IF EXISTS chk_vuln_external_id,
    DROP CONSTRAINT IF EXISTS chk_vuln_cve_compat;

ALTER TABLE vulnerabilities ALTER COLUMN cve_id SET NOT NULL;

ALTER TABLE vulnerabilities
    DROP COLUMN IF EXISTS nicknames,
    DROP COLUMN IF EXISTS cvss_version,
    DROP COLUMN IF EXISTS origin,
    DROP COLUMN IF EXISTS merged_into_scope,
    DROP COLUMN IF EXISTS merged_into,
    DROP COLUMN IF EXISTS lifecycle,
    DROP COLUMN IF EXISTS external_id,
    DROP COLUMN IF EXISTS namespace,
    DROP COLUMN IF EXISTS kind,
    DROP COLUMN IF EXISTS scope_tenant_id,
    DROP COLUMN IF EXISTS tenant_id;

COMMENT ON TABLE vulnerabilities IS 'Global CVE vulnerability database (shared across all tenants)';
COMMENT ON COLUMN vulnerabilities.cve_id IS NULL;
