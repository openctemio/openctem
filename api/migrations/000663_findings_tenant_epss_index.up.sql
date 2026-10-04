-- RFC-048 findings filters (research 17): an index for a filterable field.
-- One statement per file: CREATE INDEX CONCURRENTLY cannot run in a
-- transaction, and it does not block writes on the live table.
-- epss_score_gte / _lte (the old epss_min) and sort=-epss_score. Partial:
-- a row without a score never matches a range.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_epss ON findings (tenant_id, epss_score) WHERE epss_score IS NOT NULL;
