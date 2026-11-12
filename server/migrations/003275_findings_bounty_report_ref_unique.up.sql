-- One finding per bug-bounty report (RFC-121): the report's intake and id
-- are unique per tenant among bug_bounty findings, so a re-import or a
-- replayed delivery updates the same row. Rows without a report object have
-- NULL keys and never conflict.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_bounty_report_ref ON findings (tenant_id, (metadata->'bounty_report'->>'intake'), (metadata->'bounty_report'->>'ref')) WHERE source = 'bug_bounty';
