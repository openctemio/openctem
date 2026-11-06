-- Queued protocol v2 sensor segments are sealed at rest with the per-tenant
-- ingest payload key (docs/rfcs/RFC-026-sensor-results-ingest.md, "Queued
-- segments at rest"). payload_key_id names the key of a sealed payload;
-- payload_bytes is the size of the decoded segment (payload_sha is over those
-- bytes), which octet_length(payload) no longer gives once it is sealed or
-- emptied.
ALTER TABLE ingest_jobs
    ADD COLUMN IF NOT EXISTS payload_key_id text,
    ADD COLUMN IF NOT EXISTS payload_bytes bigint;

-- Record the decoded size of every segment stored so far (all plaintext).
UPDATE ingest_jobs
   SET payload_bytes = octet_length(payload)
 WHERE kind = 'sensor'
   AND segment_seq IS NOT NULL
   AND payload_bytes IS NULL;

-- A sensor job already applied never reads its payload again: drop it now
-- instead of keeping it in plaintext until its report finishes. The segments
-- still waiting are sealed in place by the ingest worker on start
-- (SealPlaintextV2Payloads), in small batches.
UPDATE ingest_jobs
   SET payload = ''::bytea
 WHERE kind = 'sensor'
   AND status = 'completed'
   AND octet_length(payload) > 0;
