-- Findings list filter seen_by_sensor_id: the findings a sensor of the tenant reported (docs/architecture/finding-sightings.md).
--
-- Live impact: built CONCURRENTLY (no write lock on finding_sightings); the only statement in this file
-- because CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_finding_sightings_sensor ON finding_sightings (tenant_id, sensor_id, finding_id) WHERE sensor_id IS NOT NULL;
