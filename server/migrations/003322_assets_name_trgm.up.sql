-- Findings list search (q): trigram index on assets(name), so "name ILIKE '%text%'" can use an
-- index instead of reading every row of the tenant (api/docs/architecture/list-query-contract.md, Search).
--
-- Live impact: built CONCURRENTLY (no write lock on assets); the only statement in this file because
-- CONCURRENTLY cannot run inside a transaction. Build time grows with the table size.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_name_trgm ON assets USING gin (name gin_trgm_ops);
