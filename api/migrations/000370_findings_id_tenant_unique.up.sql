-- RFC-043 §6: finding_fingerprints references findings by (id, tenant_id), so
-- an alias can never point at another tenant's finding. A foreign key needs a
-- unique index on the referenced columns. One statement per file: CREATE INDEX
-- CONCURRENTLY cannot run inside the implicit transaction of a multi-statement
-- migration, and a plain CREATE INDEX would block finding writes while it builds.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ux_findings_id_tenant ON findings (id, tenant_id);
