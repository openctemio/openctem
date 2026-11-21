-- The freshness watch reads the newest publication date of the CVE corpus
-- and counts the CVEs published in the last 31 days, every 10 minutes
-- (docs/architecture/intelligence-feeds.md, "Freshness"). Without this
-- index both are full scans of cve_records (about 350,000 rows).
--
-- Live impact: built CONCURRENTLY (no write lock on cve_records); the only
-- statement in this file because CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cve_records_published ON cve_records (published_at);
