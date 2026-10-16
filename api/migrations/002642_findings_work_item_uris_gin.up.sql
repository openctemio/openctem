-- Inbound ticket webhooks look up every finding linked to one issue URL
-- (work_item_uris @> ARRAY[url]); a GIN index serves that containment test.
-- Partial: most findings have no ticket.
--
-- CONCURRENTLY keeps the table writable while it builds; it cannot run in a
-- transaction, so this file holds exactly one statement.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_work_item_uris
    ON findings USING gin (work_item_uris)
    WHERE work_item_uris IS NOT NULL;
