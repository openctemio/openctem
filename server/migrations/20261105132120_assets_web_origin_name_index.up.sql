-- Index for finding a web origin by its name (docs/architecture/web-discovery.md).
-- Path discovery reads an origin's asset on every claim and every origin check
-- by lower(rtrim(name, '/')); without an expression index each lookup reads
-- the organization's assets. Partial on the rows the lookup reads (live HTTP
-- services), so it stays small.
--
-- CONCURRENTLY keeps the table writable while it builds; it cannot run in a
-- transaction, so this file holds exactly one statement.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_web_origin_name
    ON assets (tenant_id, (lower(rtrim(name, '/'))))
    WHERE asset_type = 'service' AND sub_type = 'http' AND deleted_at IS NULL;
