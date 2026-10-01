ALTER TABLE ingest_reports DROP CONSTRAINT IF EXISTS ingest_reports_item_totals_check;
ALTER TABLE ingest_reports DROP COLUMN IF EXISTS findings_received;
ALTER TABLE ingest_reports DROP COLUMN IF EXISTS assets_received;
