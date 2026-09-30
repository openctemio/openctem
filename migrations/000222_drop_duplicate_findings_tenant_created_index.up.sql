-- idx_findings_tenant_created_at (000049) and idx_findings_tenant_created
-- (000206) are the same btree on findings (tenant_id, created_at DESC). The
-- duplicate only costs write amplification on every findings insert/update;
-- the planner uses idx_findings_tenant_created for the same queries.
DROP INDEX CONCURRENTLY IF EXISTS idx_findings_tenant_created_at;
