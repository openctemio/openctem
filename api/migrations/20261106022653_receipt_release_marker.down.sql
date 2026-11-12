ALTER TABLE ingest_receipt_tools DROP CONSTRAINT IF EXISTS chk_ingest_receipt_tools_released;
ALTER TABLE ingest_receipt_tools DROP COLUMN IF EXISTS released_reports;
ALTER TABLE ingest_receipts DROP COLUMN IF EXISTS released_from_quarantine;
