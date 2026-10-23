-- CI results and file imports accepted fast and applied by the ingest worker
-- (docs/rfcs/RFC-122-ingest-receipts.md, "Accept fast, apply async").
--
-- POST /ci/runs/{id}/results and POST /findings/imports used to apply the
-- report inside the request. They now store the raw report, answer 202 with
-- a receipt and enqueue one job on the existing ingest_jobs queue:
--
--   ingest_jobs.kind        what the job applies: a sensor report (every row
--                           so far), a CI run's results, a file import.
--   ingest_jobs.source_ref  the CI run or the upload receipt the job belongs
--                           to (the gate waits on a run's jobs).
--   ingest_jobs.submitted_by the principal that sent it (digest dedup of a
--                           retry without an Idempotency-Key).
--   ingest_jobs.public_error a fixed code shown to the client when the job
--                           failed for good (never the internal error text).
--   ingest_payloads         the raw report, compressed and sealed with a
--                           per-tenant key (AES-256-GCM), one row per part,
--                           deleted once the job is applied.
--   ingest_receipts.status  gains 'queued': accepted, not yet picked up.
--
-- Live impact: three nullable columns and one defaulted column on
-- ingest_jobs (a metadata-only change on PostgreSQL 11+), a partial index on
-- rows that do not exist yet (no existing row has a source_ref), one new
-- empty table, and a check constraint swap on ingest_receipts validated
-- against the existing rows (all are processing/completed/failed). No
-- backfill.

ALTER TABLE ingest_jobs
    ADD COLUMN IF NOT EXISTS kind         varchar(16) NOT NULL DEFAULT 'sensor',
    ADD COLUMN IF NOT EXISTS source_ref   varchar(64),
    ADD COLUMN IF NOT EXISTS submitted_by varchar(80),
    ADD COLUMN IF NOT EXISTS public_error varchar(48);

ALTER TABLE ingest_jobs
    ADD CONSTRAINT chk_ingest_jobs_kind CHECK (kind IN ('sensor', 'ci_results', 'finding_import'));

-- The gate and the status reads look a run's (or an upload's) jobs up.
CREATE INDEX IF NOT EXISTS ix_ingest_jobs_source_ref
    ON ingest_jobs (tenant_id, kind, source_ref)
    WHERE source_ref IS NOT NULL;

COMMENT ON COLUMN ingest_jobs.kind IS
    'What the job applies: sensor (a sensor report, protocol v1 or v2), ci_results (a CI run''s uploaded results), finding_import (a POST /findings/imports upload).';
COMMENT ON COLUMN ingest_jobs.source_ref IS
    'The CI run id (ci_results) or the upload receipt id (finding_import) the job belongs to; NULL for sensor jobs.';
COMMENT ON COLUMN ingest_jobs.public_error IS
    'Fixed code a client sees when the job failed for good (unreadable, out_of_scope, run_evaluated, apply_failed, ...); the internal error stays in error.';

CREATE TABLE IF NOT EXISTS ingest_payloads (
    job_id     uuid        NOT NULL,
    part       smallint    NOT NULL,
    tenant_id  uuid        NOT NULL,
    name       varchar(255) NOT NULL DEFAULT '',
    key_id     varchar(16) NOT NULL,
    size_bytes bigint      NOT NULL,
    digest     bytea       NOT NULL,
    sealed     bytea       NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT pk_ingest_payloads PRIMARY KEY (job_id, part),
    CONSTRAINT fk_ingest_payloads_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT chk_ingest_payloads_part CHECK (part >= 0 AND part < 64),
    CONSTRAINT chk_ingest_payloads_size CHECK (size_bytes >= 0 AND size_bytes <= 134217728),
    CONSTRAINT chk_ingest_payloads_digest CHECK (octet_length(digest) = 32)
);

-- Sealed bytes do not compress: store them out of line without trying.
ALTER TABLE ingest_payloads ALTER COLUMN sealed SET STORAGE EXTERNAL;

CREATE INDEX IF NOT EXISTS ix_ingest_payloads_tenant ON ingest_payloads (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ingest_payloads_expires ON ingest_payloads (expires_at);

COMMENT ON TABLE ingest_payloads IS
    'Raw reports of queued CI results and file imports (one row per uploaded part), gzip-compressed and sealed with AES-256-GCM under a key derived per tenant from APP_ENCRYPTION_KEY. Deleted once the job is applied; kept until expires_at when it failed. A row is written before its job (a part is stored as the upload streams in), so there is no foreign key to ingest_jobs.';
COMMENT ON COLUMN ingest_payloads.key_id IS
    'Which master key sealed the row (a short fingerprint), so a key rotation still opens rows sealed under the previous key.';
COMMENT ON COLUMN ingest_payloads.digest IS
    'SHA-256 of the plaintext part; checked after opening.';

ALTER TABLE ingest_receipts DROP CONSTRAINT IF EXISTS chk_ingest_receipts_status;
ALTER TABLE ingest_receipts
    ADD CONSTRAINT chk_ingest_receipts_status CHECK (status IN ('queued', 'processing', 'completed', 'failed'));
