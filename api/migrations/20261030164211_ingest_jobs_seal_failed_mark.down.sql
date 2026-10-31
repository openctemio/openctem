-- The emptied payloads of applied v1 sensor jobs are not restored (nothing
-- reads them).
ALTER TABLE ingest_jobs DROP COLUMN IF EXISTS payload_seal_failed_at;
