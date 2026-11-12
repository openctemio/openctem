-- Findings list filter seen_by_channel (and a channel's sender): the findings a channel reported (docs/architecture/finding-sightings.md).
--
-- Live impact: built CONCURRENTLY (no write lock on finding_sightings); the only statement in this file
-- because CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_finding_sightings_channel ON finding_sightings (tenant_id, channel, sender, finding_id);
