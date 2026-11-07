-- Findings list filter seen_by_tool: the findings a tool reported, from any channel (docs/architecture/finding-sightings.md).
--
-- Live impact: built CONCURRENTLY (no write lock on finding_sightings); the only statement in this file
-- because CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_finding_sightings_tool ON finding_sightings (tenant_id, tool, finding_id);
