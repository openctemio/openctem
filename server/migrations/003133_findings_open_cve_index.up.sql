-- The emerging-threat planner (RFC-117) finds the organizations with an open
-- finding for one CVE; the existing index is led by tenant_id. CONCURRENTLY
-- keeps findings writable while it builds; one statement per file.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_cve_tenant ON findings (cve_id, tenant_id) WHERE cve_id IS NOT NULL;
