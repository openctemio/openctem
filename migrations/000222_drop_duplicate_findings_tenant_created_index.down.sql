CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_created_at
  ON findings (tenant_id, created_at DESC);
