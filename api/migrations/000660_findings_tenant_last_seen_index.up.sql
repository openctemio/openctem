-- RFC-048 findings filters (research 17): an index for a filterable field.
-- One statement per file: CREATE INDEX CONCURRENTLY cannot run in a
-- transaction, and it does not block writes on the live table.
-- last_seen_at_gte / _lte and sort=-last_seen_at.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_last_seen ON findings (tenant_id, last_seen_at DESC);
