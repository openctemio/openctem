-- The held findings of a tenant: the "Held" filter and its count
-- (docs/architecture/held-findings.md). Partial: held rows are few.
--
-- Live impact: built CONCURRENTLY (no write lock on findings); the only
-- statement in this file because CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_held ON findings (tenant_id, status) WHERE verification_state = 'held';
