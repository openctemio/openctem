CREATE UNIQUE INDEX IF NOT EXISTS ux_finding_status_approvals_actor_pending
    ON finding_status_approvals (tenant_id, finding_id)
    WHERE status = 'pending' AND requested_by_actor IS NOT NULL;

DROP INDEX IF EXISTS idx_finding_status_approvals_pending_decide_by;
DROP INDEX IF EXISTS ux_finding_status_approvals_pending;
