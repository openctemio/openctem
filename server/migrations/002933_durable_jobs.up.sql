-- Durable background jobs (api/docs/architecture/durable-jobs.md).
--
-- Outbound ticket status sync (Jira, GitHub Issues) and invitation e-mails
-- were only queued in Redis: a Redis restart or eviction, or a failed
-- enqueue (only logged), lost them. A job is now a row written in the same
-- transaction as the change that needs it (the finding status write, the
-- invitation insert or token rotation), and a worker claims rows with
-- FOR UPDATE SKIP LOCKED, retries with backoff and keeps the ones it gives
-- up on as 'dead' with their last error.
--
-- Live impact: a new, empty table. No change to existing tables.

CREATE TABLE IF NOT EXISTS durable_jobs (
    id              uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id       uuid        NOT NULL,
    kind            text        NOT NULL,
    -- The finding (status sync) or invitation (e-mail) the job is about.
    subject_id      uuid        NOT NULL,
    -- Kind-specific data, sealed with the application encryption key when
    -- it holds a secret (the invitation link token). Cleared on 'dead'.
    payload         text,
    status          text        NOT NULL DEFAULT 'pending',
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    -- A claimed job whose lease passed (worker died) is claimed again.
    locked_until    timestamptz,
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_durable_jobs PRIMARY KEY (id),
    CONSTRAINT fk_durable_jobs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT chk_durable_jobs_kind CHECK (kind IN ('jira_status_sync', 'github_status_sync', 'invitation_email')),
    CONSTRAINT chk_durable_jobs_status CHECK (status IN ('pending', 'processing', 'dead'))
);

-- One pending job per subject and kind: a burst of status changes queues one
-- push (the worker reads the current status), and a resent invitation
-- replaces the unsent e-mail of its rotated token.
CREATE UNIQUE INDEX IF NOT EXISTS uq_durable_jobs_pending_subject
    ON durable_jobs (kind, subject_id) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_durable_jobs_claim
    ON durable_jobs (next_attempt_at) WHERE status IN ('pending', 'processing');

CREATE INDEX IF NOT EXISTS idx_durable_jobs_tenant ON durable_jobs (tenant_id);

COMMENT ON TABLE durable_jobs IS
    'Background jobs that must not be lost (ticket status sync, invitation e-mail), written in the transaction of the change that needs them.';
