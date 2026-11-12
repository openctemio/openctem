-- Saved views for the asset inventory and the scans list (both on the list
-- query contract, docs/architecture/list-query-contract.md).
--
-- Live impact: replaces one CHECK constraint on saved_views (a small table);
-- every existing row (findings, vulnerabilities) satisfies the new one.
ALTER TABLE saved_views DROP CONSTRAINT IF EXISTS chk_saved_views_page;
ALTER TABLE saved_views ADD CONSTRAINT chk_saved_views_page
    CHECK (page IN ('findings', 'vulnerabilities', 'assets', 'scans'));
