CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_id_pk ON findings (tenant_id, id);
