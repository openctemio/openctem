DELETE FROM dash_ingest_day WHERE source_kind = 'platform';
ALTER TABLE dash_ingest_day DROP CONSTRAINT IF EXISTS chk_dash_ingest_day_kind;
ALTER TABLE dash_ingest_day ADD CONSTRAINT chk_dash_ingest_day_kind
    CHECK (source_kind IN ('sensor', 'import', 'connector', 'ci'));

DELETE FROM ingest_receipts WHERE source_kind = 'platform';
ALTER TABLE ingest_receipts DROP CONSTRAINT IF EXISTS chk_ingest_receipts_source_kind;
ALTER TABLE ingest_receipts ADD CONSTRAINT chk_ingest_receipts_source_kind
    CHECK (source_kind IN ('upload', 'scan_run', 'command', 'ci_run', 'connector', 'sensor'));

DROP TABLE IF EXISTS ingest_receipt_tools;
