-- The in-place sealing of queued sensor payloads (SealPlaintextSensorPayloads)
-- marks a row it could not seal, so that one unsealable row neither stalls
-- the rows behind it nor is picked again at every run. The mark expires: the
-- row is tried again a day later (for instance after a key was fixed).
ALTER TABLE ingest_jobs
    ADD COLUMN IF NOT EXISTS payload_seal_failed_at timestamptz;

-- A protocol v1 sensor job already applied never reads its payload again
-- (Complete now empties it like a v2 segment): drop what is still stored in
-- plaintext. The v1 jobs still waiting are sealed in place by the ingest
-- worker, in small batches.
UPDATE ingest_jobs
   SET payload = ''::bytea
 WHERE kind = 'sensor'
   AND ingest_report_id IS NULL
   AND status = 'completed'
   AND octet_length(payload) > 0;
