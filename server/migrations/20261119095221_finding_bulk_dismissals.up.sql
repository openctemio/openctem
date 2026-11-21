-- finding_bulk_dismissals: one bulk "Dismiss" of findings (false positive or
-- accepted risk) a person made from the findings list
-- (docs/architecture/findings-bulk-by-filter.md, "Bulk dismiss"). The row is
-- the idempotency record (a retry with the same key returns the stored
-- result), the per-person daily budget of findings decided alone (the sum of
-- decided_count over 24 hours, read under an advisory lock), and what an undo
-- reopens (decided_ids). The note stays on each finding's timeline only.
-- Approval groups gain the source type 'selection' (a bulk dismiss's members
-- that need a second person).
--
-- Live impact: a new, empty table, and a wider CHECK on approval_batches
-- (existing rows satisfy it).

CREATE TABLE IF NOT EXISTS finding_bulk_dismissals (
    id               uuid        NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id        uuid        NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    created_by       uuid        NOT NULL,
    idempotency_key  text        CHECK (idempotency_key IS NULL OR char_length(idempotency_key) BETWEEN 1 AND 128),
    -- Hash of the request the key was first used with: the same key with
    -- another request is refused.
    request_hash     text        NOT NULL CHECK (char_length(request_hash) <= 64),
    requested_status text        NOT NULL CHECK (requested_status IN ('false_positive', 'accepted')),
    closure_reason   text        NOT NULL CHECK (char_length(closure_reason) <= 64),
    source_label     text        NOT NULL DEFAULT '' CHECK (char_length(source_label) <= 200),
    filter_hash      text        CHECK (filter_hash IS NULL OR char_length(filter_hash) <= 64),
    -- The findings this bulk decided alone (what an undo may reopen).
    decided_ids      uuid[]      NOT NULL DEFAULT '{}',
    -- The approval group of the members that need a second person.
    batch_id         uuid,
    -- The response of the apply, returned verbatim on a replay.
    result           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- decided_count is reserved when the row is inserted (the budget) and
    -- set to the findings actually decided alone when the apply ends.
    decided_count    integer     NOT NULL DEFAULT 0 CHECK (decided_count >= 0),
    grouped_count    integer     NOT NULL DEFAULT 0 CHECK (grouped_count >= 0),
    skipped_count    integer     NOT NULL DEFAULT 0 CHECK (skipped_count >= 0),
    status           text        NOT NULL DEFAULT 'applied' CHECK (status IN ('applied', 'undone')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    undone_at        timestamptz,
    undone_by        uuid,
    CONSTRAINT pk_finding_bulk_dismissals PRIMARY KEY (id)
);

-- Replays: one row per person and key.
CREATE UNIQUE INDEX IF NOT EXISTS uq_finding_bulk_dismissals_idempotency
    ON finding_bulk_dismissals (tenant_id, created_by, idempotency_key) WHERE idempotency_key IS NOT NULL;

-- The person's rolling 24-hour budget, and undo by creator.
CREATE INDEX IF NOT EXISTS idx_finding_bulk_dismissals_creator
    ON finding_bulk_dismissals (tenant_id, created_by, created_at);

COMMENT ON TABLE finding_bulk_dismissals IS
    'Bulk dismissals of findings: idempotency record, daily budget of findings decided alone, and what an undo reopens.';

ALTER TABLE approval_batches DROP CONSTRAINT IF EXISTS chk_approval_batches_source;
ALTER TABLE approval_batches ADD CONSTRAINT chk_approval_batches_source
    CHECK (source_type IN ('remediation_task', 'vulnerability_selection', 'selection'));
