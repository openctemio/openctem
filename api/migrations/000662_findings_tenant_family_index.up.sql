-- RFC-048 family filter and group-by. One statement per file:
-- CREATE INDEX CONCURRENTLY cannot run in a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_family ON findings (tenant_id, family) WHERE family IS NOT NULL;
