-- Findings list filter seen_by_scan_id: the findings a scan definition's runs reported (docs/architecture/finding-sightings.md).
--
-- Live impact: built CONCURRENTLY (no write lock on finding_sightings); the only statement in this file
-- because CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_finding_sightings_scan ON finding_sightings (tenant_id, scan_id, finding_id) WHERE scan_id IS NOT NULL;
