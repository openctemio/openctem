-- RFC-044 §5.1: one definition per (tenant, namespace, external_id) among a
-- tenant's own definitions. A tenant definition may share its id with a
-- global one (a custom template named like a curated one); lookups resolve
-- the global one first. One statement per file, CONCURRENTLY.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ux_vulnerabilities_tenant_identity ON vulnerabilities (tenant_id, namespace, external_id) WHERE tenant_id IS NOT NULL;
