-- RFC-005: Asynchronous ingest. Queue table that decouples accept (fast, in
-- request) from process (async worker pool). Mirrors the notification_outbox
-- FOR UPDATE SKIP LOCKED pattern.

CREATE TABLE IF NOT EXISTS ingest_jobs (
    id            UUID PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    agent_id      UUID,
    report_id     TEXT NOT NULL DEFAULT '',
    source_type   TEXT NOT NULL DEFAULT '',
    payload       BYTEA NOT NULL,            -- decompressed CTIS JSON
    payload_sha   BYTEA NOT NULL,            -- sha256(payload): idempotency + integrity
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending|processing|completed|failed|dead
    attempts      INT  NOT NULL DEFAULT 0,
    max_attempts  INT  NOT NULL DEFAULT 5,
    priority      INT  NOT NULL DEFAULT 0,
    result        JSONB,                     -- ingest counts on success
    error         TEXT,                      -- last error message on failure
    locked_by     TEXT,                      -- worker/replica id holding the claim
    locked_at     TIMESTAMPTZ,
    available_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- backoff gate: not claimable before this
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ingest_jobs_status_check
        CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'dead'))
);

-- Idempotency: the same payload submitted twice maps to one job, processed once.
CREATE UNIQUE INDEX IF NOT EXISTS ux_ingest_jobs_idem
    ON ingest_jobs (tenant_id, report_id, payload_sha);

-- Claim scan: pending/processing jobs that are due, oldest first. Partial index
-- keeps it small (terminal rows are excluded).
CREATE INDEX IF NOT EXISTS ix_ingest_jobs_claim
    ON ingest_jobs (available_at)
    WHERE status IN ('pending', 'processing');

-- Per-tenant queue-depth checks and fair-queue partitioning.
CREATE INDEX IF NOT EXISTS ix_ingest_jobs_tenant_status
    ON ingest_jobs (tenant_id, status);
