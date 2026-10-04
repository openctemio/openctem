-- RFC-048 findings filters (research 17): an index for a filterable field.
-- One statement per file: CREATE INDEX CONCURRENTLY cannot run in a
-- transaction, and it does not block writes on the live table.
-- cvss_score_gte / _lte and sort=-cvss_score. Partial: a row without a
-- score never matches a range.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_cvss ON findings (tenant_id, cvss_score) WHERE cvss_score IS NOT NULL;
