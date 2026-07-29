-- expand-contract-ok: down leg of an expand-only migration; runs on an explicit
-- rollback, never during a forward deploy. The index is dropped by 000198's
-- own down leg.
ALTER TABLE findings DROP COLUMN IF EXISTS ingest_channel;
