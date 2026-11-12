-- Global CVE catalog rows a tenant report created become identity stubs
-- (docs/architecture/global-catalog-trust.md, RFC-044 §5.5).
--
-- Until now the first tenant report naming a CVE wrote its own title,
-- description, CVSS, references, versions and dates into the shared row
-- (origin 'report'), and every organization read that text through the CVE
-- catalog. This migration:
--   1. archives the report-written content of those rows (platform table, no
--      API reads it; the down migration restores from it);
--   2. resets them to identity stubs (title = the CVE id, or the CISA KEV name;
--      no description but the CISA KEV one; no CVSS, references, versions,
--      remediation or dates);
--   3. fills the stubs whose CVE the corpus (cve_records) already holds from
--      it (origin 'nvd'), as the corpus import does from now on.
-- The reporting organization keeps its own text on its findings, which never
-- read it from the catalog row. Risk columns (EPSS, KEV, exploit flags) are
-- already feed-only (migration 000233) and are not touched.
--
-- Live impact: one UPDATE over the report-created global CVE rows (the
-- catalog's smaller part; the corpus creates the rest). A new archive table.

SET LOCAL lock_timeout = '10s';

CREATE TABLE IF NOT EXISTS vulnerability_report_content_archive (
    vulnerability_id  uuid PRIMARY KEY REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cve_id            varchar(30) NOT NULL,
    title             varchar(500) NOT NULL,
    description       text,
    severity          varchar(20) NOT NULL,
    cvss_score        numeric(3,1),
    cvss_vector       varchar(200),
    cvss_version      varchar(10),
    aliases           text[],
    reference_urls    jsonb NOT NULL,
    affected_versions jsonb NOT NULL,
    fixed_versions    text[],
    remediation       text,
    published_at      timestamptz,
    modified_at       timestamptz,
    archived_at       timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE vulnerability_report_content_archive IS
    'Tenant-report content removed from global CVE catalog rows by migration catalog_report_stubs; restored by its down migration. No API reads it; dropped by a later contract migration.';

INSERT INTO vulnerability_report_content_archive (
    vulnerability_id, cve_id, title, description, severity, cvss_score, cvss_vector, cvss_version,
    aliases, reference_urls, affected_versions, fixed_versions, remediation, published_at, modified_at)
SELECT id, cve_id, title, description, severity, cvss_score, cvss_vector, cvss_version,
    aliases, reference_urls, affected_versions, fixed_versions, remediation, published_at, modified_at
FROM vulnerabilities
WHERE tenant_id IS NULL AND cve_id IS NOT NULL AND origin = 'report'
ON CONFLICT (vulnerability_id) DO NOTHING;

UPDATE vulnerabilities v SET
    title = LEFT(COALESCE((SELECT NULLIF(k.vulnerability_name, '') FROM kev_catalog k WHERE k.cve_id = v.cve_id), v.cve_id), 500),
    description = (SELECT NULLIF(k.short_description, '') FROM kev_catalog k WHERE k.cve_id = v.cve_id),
    severity = 'unknown',
    cvss_score = NULL, cvss_vector = NULL, cvss_version = NULL,
    aliases = '{}', reference_urls = '[]', affected_versions = '[]', fixed_versions = '{}',
    remediation = NULL, published_at = NULL, modified_at = NULL
WHERE v.tenant_id IS NULL AND v.cve_id IS NOT NULL AND v.origin = 'report';

-- Same statement as fillCatalogStubsSQL (internal/infra/postgres/catalog_stub.go),
-- for every stub at once.
UPDATE vulnerabilities v SET
    title = LEFT(COALESCE(NULLIF(k.vulnerability_name, ''), c.cve_id), 500),
    description = NULLIF(c.description, ''),
    severity = CASE WHEN c.severity IN ('critical', 'high', 'medium', 'low') THEN c.severity
                    WHEN c.severity = 'none' THEN 'info' ELSE 'unknown' END,
    cvss_score = c.cvss_score, cvss_vector = c.cvss_vector, cvss_version = c.cvss_version,
    published_at = c.published_at, modified_at = c.last_modified_at,
    origin = 'nvd'
FROM cve_records c
LEFT JOIN kev_catalog k ON k.cve_id = c.cve_id
WHERE v.cve_id = c.cve_id AND v.tenant_id IS NULL AND v.origin = 'report';
