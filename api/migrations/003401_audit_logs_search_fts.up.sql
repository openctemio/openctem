-- Audit log search: a GIN index on the exact text-search expression the
-- search box uses (audit_repository.go, SearchTerm). Without it every search
-- computed to_tsvector for each of the tenant's audit rows (0.8-2.5 s at
-- 300k rows, 0.2 ms with the index).
--
-- Live impact: built CONCURRENTLY (no write lock on audit_logs); the only
-- statement in this file. Each audit insert also writes this index (GIN
-- fast update batches it); about 60 bytes per audit row.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_search_fts ON audit_logs USING gin (
    to_tsvector('english', COALESCE(message, '') || ' ' || COALESCE(resource_name, '') || ' ' || COALESCE(actor_email, ''))
);
