-- Lists and counts by sub-status, and the archive check (is a sub-status in
-- use?), on the findings that carry one. Built concurrently so the large
-- table stays writable; CONCURRENTLY cannot run in a transaction, so this
-- file holds exactly one statement.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_sub_status ON findings (tenant_id, sub_status_id) WHERE sub_status_id IS NOT NULL;
