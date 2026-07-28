-- expand-contract-ok: down leg of an expand-only migration; runs on an explicit
-- rollback, never during a forward deploy.
DROP INDEX CONCURRENTLY IF EXISTS idx_findings_tenant_ingest_channel;
ALTER TABLE findings DROP COLUMN IF EXISTS ingest_channel;
