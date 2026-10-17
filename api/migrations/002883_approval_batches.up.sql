-- Group-level exceptions (api/docs/rfcs/RFC-111-approval-policy.md §7): one
-- request to accept the risk of, or mark false positive, the open findings of
-- a remediation task, decided once. The batch holds the request; each member
-- finding gets its own pending finding_status_approvals row linked by
-- batch_id (decided only with the batch, then an ordinary decision with its
-- own end, expiry and material-change check).
--
-- Live impact: a new empty table; one nullable column on
-- finding_status_approvals (catalog change) and its foreign key added NOT
-- VALID (validated by the next migration); a partial index on the column,
-- built in place (approvals are rare: the table is small).

CREATE TABLE IF NOT EXISTS approval_batches (
    id                 uuid        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id          uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_type        varchar(32) NOT NULL,
    source_id          uuid        NOT NULL,
    requested_status   text        NOT NULL,
    closure_reason     varchar(64) NOT NULL,
    justification      text        NOT NULL,
    expires_at         timestamptz,
    requested_by       uuid        REFERENCES users(id) ON DELETE SET NULL,
    tier               varchar(16) NOT NULL,
    risk_class         varchar(16) NOT NULL,
    required_approvals smallint    NOT NULL,
    policy_eval        jsonb,
    status             varchar(16) NOT NULL DEFAULT 'pending',
    decide_by          timestamptz NOT NULL,
    member_count       integer     NOT NULL,
    decided_by         uuid        REFERENCES users(id) ON DELETE SET NULL,
    decided_at         timestamptz,
    rejection_reason   text,
    version            integer     NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_approval_batches_tenant_id UNIQUE (tenant_id, id),
    CONSTRAINT chk_approval_batches_source CHECK (source_type IN ('remediation_task')),
    CONSTRAINT chk_approval_batches_requested_status CHECK (requested_status IN ('accepted', 'false_positive')),
    CONSTRAINT chk_approval_batches_tier CHECK (tier IN ('peer', 'security', 'dual')),
    CONSTRAINT chk_approval_batches_required CHECK (required_approvals BETWEEN 1 AND 2),
    CONSTRAINT chk_approval_batches_status CHECK (status IN ('pending', 'approved', 'rejected', 'canceled', 'expired')),
    CONSTRAINT chk_approval_batches_members CHECK (member_count BETWEEN 1 AND 500),
    CONSTRAINT chk_approval_batches_accept_end CHECK (requested_status <> 'accepted' OR expires_at IS NOT NULL)
);

-- One pending exception per task.
CREATE UNIQUE INDEX IF NOT EXISTS ux_approval_batches_pending_source
    ON approval_batches (tenant_id, source_type, source_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_approval_batches_tenant_status
    ON approval_batches (tenant_id, status, created_at DESC);

ALTER TABLE finding_status_approvals ADD COLUMN IF NOT EXISTS batch_id uuid;
ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS fk_finding_status_approvals_batch;
ALTER TABLE finding_status_approvals ADD CONSTRAINT fk_finding_status_approvals_batch
    FOREIGN KEY (tenant_id, batch_id) REFERENCES approval_batches (tenant_id, id) ON DELETE CASCADE NOT VALID;
CREATE INDEX IF NOT EXISTS idx_finding_status_approvals_batch
    ON finding_status_approvals (tenant_id, batch_id) WHERE batch_id IS NOT NULL;

COMMENT ON TABLE approval_batches IS
    'Group-level exception requests (RFC-111 §7): one decision over the open findings of a remediation task';
COMMENT ON COLUMN finding_status_approvals.batch_id IS
    'The group exception this member request belongs to; decided only with the batch';
