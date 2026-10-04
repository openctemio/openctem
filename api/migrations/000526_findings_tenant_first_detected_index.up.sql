-- RFC-048 findings filters (research 17): an index for a filterable field.
-- One statement per file: CREATE INDEX CONCURRENTLY cannot run in a
-- transaction, and it does not block writes on the live table.
-- first_detected_at_gte / _lte and sort=-first_detected_at. The older
-- idx_findings_first_detected is not tenant-led.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_first_detected ON findings (tenant_id, first_detected_at DESC);
