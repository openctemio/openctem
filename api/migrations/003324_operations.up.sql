-- Operations: long-running work a person started from the API, read back
-- with GET /api/v1/operations/{id} (docs/architecture/operations.md). The
-- first kinds are bulk changes of findings selected by a filter.
--
-- Live impact: a new, empty table. No change to existing tables.

CREATE TABLE IF NOT EXISTS operations (
    id              uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id       uuid        NOT NULL,
    created_by      uuid        NOT NULL,
    kind            varchar(40) NOT NULL,
    status          varchar(16) NOT NULL DEFAULT 'running',
    -- Replays of the same request (same key, same creator) return this row.
    idempotency_key varchar(128),
    -- Hash of the request the key was first used with: the same key with
    -- another request is refused.
    request_hash    varchar(64) NOT NULL DEFAULT '',
    total           integer     NOT NULL DEFAULT 0,
    processed       integer     NOT NULL DEFAULT 0,
    succeeded       integer     NOT NULL DEFAULT 0,
    skipped         integer     NOT NULL DEFAULT 0,
    failed          integer     NOT NULL DEFAULT 0,
    -- Per-item outcomes that were not a success (at most 200), and the
    -- reason a whole operation failed.
    result          jsonb       NOT NULL DEFAULT '{}'::jsonb,
    error           varchar(500) NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- Moves on every processed chunk; a running row that stops moving was
    -- interrupted (the API process stopped).
    updated_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    CONSTRAINT pk_operations PRIMARY KEY (id),
    CONSTRAINT fk_operations_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_operations_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT chk_operations_kind CHECK (kind IN ('findings_bulk_status', 'findings_bulk_assign')),
    CONSTRAINT chk_operations_status CHECK (status IN ('running', 'succeeded', 'failed', 'interrupted')),
    CONSTRAINT chk_operations_counts CHECK (total >= 0 AND processed >= 0 AND succeeded >= 0 AND skipped >= 0 AND failed >= 0)
);

-- Replays: one row per creator and key.
CREATE UNIQUE INDEX IF NOT EXISTS uq_operations_idempotency
    ON operations (tenant_id, created_by, idempotency_key) WHERE idempotency_key IS NOT NULL;

-- One running operation per person.
CREATE UNIQUE INDEX IF NOT EXISTS uq_operations_running_creator
    ON operations (tenant_id, created_by) WHERE status = 'running';

-- The tenant's hourly budget of bulk rows.
CREATE INDEX IF NOT EXISTS idx_operations_tenant_created ON operations (tenant_id, created_at);

CREATE INDEX IF NOT EXISTS idx_operations_created_by ON operations (created_by);

COMMENT ON TABLE operations IS
    'Long-running work a person started (bulk changes of findings by filter); readable by its creator only.';
