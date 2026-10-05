-- RFC-044 §5.5: the tables that point at a definition reference it by
-- (id, scope_tenant_id), so the schema itself proves the definition is global
-- or the referencing row's own tenant's (000823). A foreign key needs a unique
-- index on the referenced columns. One statement per file: CREATE INDEX
-- CONCURRENTLY cannot run inside the implicit transaction of a multi-statement
-- migration, and a plain CREATE INDEX would block catalog writes while it builds.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ux_vulnerabilities_id_scope ON vulnerabilities (id, scope_tenant_id);
