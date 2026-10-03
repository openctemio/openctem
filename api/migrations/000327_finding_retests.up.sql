-- RFC-039: continuous retest with regression reopen.
--
-- finding_retests: one row per retest attempt of one finding. A retest re-runs
-- the finding's own nuclei template against its target and probes the target's
-- reachability (two `validate` commands), then settles the finding:
-- fixed / still_present / unknown. Unreachable is unknown, never fixed.
--
-- finding_retest_cursors: the auto-retest scheduler's per-tenant tick. Every
-- API replica runs the scheduler; a replica queues a tenant's retests only after
-- moving next_run_at from the value it read (compare-and-set), so a tick fires
-- once however many replicas list it.

CREATE TABLE IF NOT EXISTS finding_retests (
    id               UUID PRIMARY KEY,
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id       UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    asset_id         UUID REFERENCES assets(id) ON DELETE SET NULL,
    trigger          VARCHAR(16) NOT NULL,
    requested_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    status           VARCHAR(16) NOT NULL DEFAULT 'pending',
    outcome          VARCHAR(16),
    reason           TEXT,
    prior_status     VARCHAR(30) NOT NULL,
    result_status    VARCHAR(30),
    template_id      VARCHAR(255) NOT NULL,
    target           TEXT NOT NULL,
    check_command_id UUID,
    reach_command_id UUID,
    deadline_at      TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMPTZ,

    CONSTRAINT chk_finding_retests_trigger CHECK (trigger IN ('manual', 'auto')),
    CONSTRAINT chk_finding_retests_status CHECK (status IN ('pending', 'completed')),
    CONSTRAINT chk_finding_retests_outcome CHECK (outcome IS NULL OR outcome IN ('fixed', 'still_present', 'unknown')),
    CONSTRAINT chk_finding_retests_completed CHECK (
        (status = 'pending' AND outcome IS NULL AND completed_at IS NULL)
        OR (status = 'completed' AND outcome IS NOT NULL AND completed_at IS NOT NULL)
    )
);

-- One retest in flight per finding: a second request is refused, a second
-- scheduler cannot queue it again.
CREATE UNIQUE INDEX IF NOT EXISTS ux_finding_retests_one_pending
    ON finding_retests (finding_id) WHERE status = 'pending';

-- History on the finding page, newest first.
CREATE INDEX IF NOT EXISTS idx_finding_retests_finding
    ON finding_retests (tenant_id, finding_id, created_at DESC);

-- In-flight caps (per tenant, per asset) and the stale sweep.
CREATE INDEX IF NOT EXISTS idx_finding_retests_pending
    ON finding_retests (tenant_id, trigger, asset_id, deadline_at) WHERE status = 'pending';

-- Daily auto budget per tenant.
CREATE INDEX IF NOT EXISTS idx_finding_retests_tenant_created
    ON finding_retests (tenant_id, trigger, created_at);

-- Command → retest lookup when a sensor completes a command.
CREATE INDEX IF NOT EXISTS idx_finding_retests_check_cmd
    ON finding_retests (check_command_id) WHERE check_command_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_finding_retests_reach_cmd
    ON finding_retests (reach_command_id) WHERE reach_command_id IS NOT NULL;

COMMENT ON TABLE finding_retests IS
    'RFC-039: one retest attempt of a finding (template re-run + reachability probe) and its outcome';

CREATE TABLE IF NOT EXISTS finding_retest_cursors (
    tenant_id   UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    next_run_at TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE finding_retest_cursors IS
    'RFC-039: auto-retest scheduler tick per tenant, claimed by compare-and-set on next_run_at';

-- Activity types for the retest trail (request + completion, actor "system: retest").
ALTER TABLE finding_activities DROP CONSTRAINT IF EXISTS chk_activity_type;
ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (
    'created', 'status_changed', 'severity_changed', 'resolved', 'reopened',
    'assigned', 'unassigned',
    'triage_updated', 'false_positive_marked', 'duplicate_marked', 'duplicate_unmarked',
    'verified', 'remediation_updated', 'metadata_updated', 'acceptance_expired',
    'comment_added', 'comment_updated', 'comment_deleted',
    'scan_detected', 'auto_resolved', 'auto_reopened',
    'linked', 'unlinked',
    'sla_warning', 'sla_breach',
    'ai_triage_requested', 'ai_triage', 'ai_triage_failed',
    'approval_requested', 'approval_approved', 'approval_rejected', 'approval_canceled',
    'retest_requested', 'retest_completed'
));
