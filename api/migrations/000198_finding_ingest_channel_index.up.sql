CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_ingest_channel ON findings (tenant_id, ingest_channel) WHERE ingest_channel IS NOT NULL;
