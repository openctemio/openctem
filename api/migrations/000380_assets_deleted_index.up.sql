-- The asset purge job finds soft-deleted assets past the retention period.
-- Partial: only deleted rows are indexed. One statement per file:
-- CREATE INDEX CONCURRENTLY cannot run in a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_deleted_at ON assets (deleted_at) WHERE deleted_at IS NOT NULL;
