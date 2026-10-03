-- The upper-casing and the catalog links are corrections and are kept. The
-- column stays VARCHAR(30): narrowing it would fail on any longer id stored
-- since, and the old width was the defect.
DROP INDEX IF EXISTS idx_findings_unlinked_cve;
