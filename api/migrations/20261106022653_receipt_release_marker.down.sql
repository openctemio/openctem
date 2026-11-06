ALTER TABLE ingest_receipt_tools DROP CONSTRAINT IF EXISTS chk_ingest_receipt_tools_merged;
ALTER TABLE ingest_receipt_tools DROP COLUMN IF EXISTS merged, DROP COLUMN IF EXISTS released_reports;
ALTER TABLE ingest_receipts DROP CONSTRAINT IF EXISTS chk_ingest_receipts_merged;
ALTER TABLE ingest_receipts DROP COLUMN IF EXISTS findings_merged, DROP COLUMN IF EXISTS released_from_quarantine;
