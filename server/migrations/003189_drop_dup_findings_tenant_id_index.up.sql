-- idx_findings_tenant_id_pk (tenant_id, id) is the same index as the unique
-- uq_findings_tenant_id_id; every findings write maintained both. One statement
-- (CONCURRENTLY cannot run in a transaction block).
DROP INDEX CONCURRENTLY IF EXISTS idx_findings_tenant_id_pk;
