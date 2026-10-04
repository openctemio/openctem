-- RFC-048 cve_id filter over every CVE of a finding (cve_ids && $1).
-- CREATE INDEX CONCURRENTLY cannot run in a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_cve_ids ON findings USING GIN (cve_ids) WHERE cve_ids IS NOT NULL;
