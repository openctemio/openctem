-- Shared claim: read each organization's oldest pending shared jobs per priority straight from an
-- index (docs/rfcs/RFC-129-shared-fleet-scheduling.md), so a shared sensor's poll looks at a few
-- jobs per organization instead of ranking every pending shared job of every organization.
--
-- Live impact: built CONCURRENTLY (no write lock on commands); the only statement in this file
-- because CONCURRENTLY cannot run inside a transaction. The index holds only pending shared jobs.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_commands_shared_pending
    ON commands (tenant_id, priority, created_at, id)
    WHERE is_platform_job = TRUE AND status = 'pending';
