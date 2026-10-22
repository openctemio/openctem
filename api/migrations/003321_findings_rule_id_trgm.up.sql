-- Findings list search (q): trigram index on findings(rule_id), so "rule_id ILIKE '%text%'" can use an
-- index instead of reading every row of the tenant (api/docs/architecture/list-query-contract.md, Search).
--
-- Live impact: built CONCURRENTLY (no write lock on findings); the only statement in this file because
-- CONCURRENTLY cannot run inside a transaction. Build time grows with the table size.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_rule_id_trgm ON findings USING gin (rule_id gin_trgm_ops);
