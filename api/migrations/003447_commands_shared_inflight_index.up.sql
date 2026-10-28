-- Shared claim: count an organization's shared jobs in flight without reading its finished ones
-- (docs/rfcs/RFC-129-shared-fleet-scheduling.md). The fair-share order and the per-organization
-- limit in ClaimManyShared count acknowledged and running shared jobs per organization; the only
-- index that matched before also held every finished shared job kept for retention.
--
-- Live impact: built CONCURRENTLY (no write lock on commands); the only statement in this file
-- because CONCURRENTLY cannot run inside a transaction. The index holds only shared jobs in
-- flight, so it stays small.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_commands_shared_inflight
    ON commands (tenant_id)
    WHERE is_platform_job = TRUE AND status IN ('acknowledged', 'running');
