-- The previous release cannot open a sealed segment: empty them (their
-- reports fail or expire and the sensor re-sends) before dropping the columns.
UPDATE ingest_jobs
   SET payload = ''::bytea
 WHERE payload_key_id IS NOT NULL;

ALTER TABLE ingest_jobs
    DROP COLUMN IF EXISTS payload_bytes,
    DROP COLUMN IF EXISTS payload_key_id;
