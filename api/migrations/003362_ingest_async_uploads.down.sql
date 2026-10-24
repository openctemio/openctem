-- Reverts 003362_ingest_async_uploads. Queued uploads are lost: their raw
-- reports are dropped with ingest_payloads and their jobs are removed, and a
-- receipt still queued is marked failed.

DELETE FROM ingest_jobs WHERE kind <> 'sensor';
UPDATE ingest_receipts SET status = 'failed', updated_at = now() WHERE status = 'queued';

ALTER TABLE ingest_receipts DROP CONSTRAINT IF EXISTS chk_ingest_receipts_status;
ALTER TABLE ingest_receipts
    ADD CONSTRAINT chk_ingest_receipts_status CHECK (status IN ('processing', 'completed', 'failed'));

DROP TABLE IF EXISTS ingest_payloads;

DROP INDEX IF EXISTS ix_ingest_jobs_source_ref;
ALTER TABLE ingest_jobs DROP CONSTRAINT IF EXISTS chk_ingest_jobs_kind;
ALTER TABLE ingest_jobs
    DROP COLUMN IF EXISTS public_error,
    DROP COLUMN IF EXISTS submitted_by,
    DROP COLUMN IF EXISTS source_ref,
    DROP COLUMN IF EXISTS kind;
