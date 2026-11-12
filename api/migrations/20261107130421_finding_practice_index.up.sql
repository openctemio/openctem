-- The practice switch of the findings list and its counts (tenant, practice,
-- status) (docs/architecture/finding-practices.md).
--
-- Live impact: built CONCURRENTLY (no write lock on findings); the only
-- statement in this file because CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_practice_status ON findings (tenant_id, practice, status);
