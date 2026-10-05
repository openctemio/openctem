-- RFC-044 §5.1: one global definition per (namespace, external_id). The CVE
-- rows are already unique through cve_id; this covers every namespace. One
-- statement per file, CONCURRENTLY: catalog writes go on while it builds.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ux_vulnerabilities_global_identity ON vulnerabilities (namespace, external_id) WHERE tenant_id IS NULL;
