-- Restores the report-written content of the global CVE rows that
-- catalog_report_stubs reset or filled, and their origin, from the archive.
-- Rows whose archive entry is gone (deleted rows) are left as they are.
SET LOCAL lock_timeout = '10s';

UPDATE vulnerabilities v SET
    title = a.title, description = a.description, severity = a.severity,
    cvss_score = a.cvss_score, cvss_vector = a.cvss_vector, cvss_version = a.cvss_version,
    aliases = COALESCE(a.aliases, '{}'), reference_urls = a.reference_urls,
    affected_versions = a.affected_versions, fixed_versions = COALESCE(a.fixed_versions, '{}'),
    remediation = a.remediation, published_at = a.published_at, modified_at = a.modified_at,
    origin = 'report'
FROM vulnerability_report_content_archive a
WHERE a.vulnerability_id = v.id AND v.tenant_id IS NULL;

DROP TABLE IF EXISTS vulnerability_report_content_archive;
