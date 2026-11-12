-- Receipts: quarantine release marker (docs/rfcs/RFC-122-ingest-receipts.md).
--
-- released_from_quarantine / released_reports: a report held in the results
-- quarantine and applied later (by the platform's auto-release or a person)
-- is recorded under its original sender, a sensor; these mark which receipts
-- and which sender rows carry such reports, so the lists can say "Released
-- from quarantine" next to the sensor instead of showing a connector.
--
-- Live impact: two new columns with constant defaults (metadata-only in
-- PostgreSQL 11+), no rewrite, no backfill.

ALTER TABLE ingest_receipts
    ADD COLUMN IF NOT EXISTS released_from_quarantine boolean NOT NULL DEFAULT false;

ALTER TABLE ingest_receipt_tools
    ADD COLUMN IF NOT EXISTS released_reports integer NOT NULL DEFAULT 0;
ALTER TABLE ingest_receipt_tools
    ADD CONSTRAINT chk_ingest_receipt_tools_released CHECK (released_reports >= 0);

COMMENT ON COLUMN ingest_receipts.released_from_quarantine IS
    'True when a report held in the results quarantine and applied later is part of this receipt; the sender is still the original sensor.';
