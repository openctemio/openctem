DROP INDEX IF EXISTS idx_findings_tenant_exploit;
DROP INDEX IF EXISTS idx_findings_cve_ids;
DROP INDEX IF EXISTS idx_findings_tenant_family;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_cve_ids_len;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_vpr_score;
ALTER TABLE findings
    DROP COLUMN IF EXISTS patch_published_at,
    DROP COLUMN IF EXISTS cve_ids,
    DROP COLUMN IF EXISTS cvss_version,
    DROP COLUMN IF EXISTS vpr_score,
    DROP COLUMN IF EXISTS exploit_available,
    DROP COLUMN IF EXISTS family;
