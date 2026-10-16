-- At most one pending request per finding, whoever made it (a person or a
-- platform actor). It replaces the actor-only index of migration
-- approval_requested_by_actor. The partial index on decide_by serves the
-- hourly expiry of overdue requests.
--
-- Live impact: the table is small; duplicates were cancelled by the previous
-- migration.

CREATE UNIQUE INDEX IF NOT EXISTS ux_finding_status_approvals_pending
    ON finding_status_approvals (tenant_id, finding_id)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_finding_status_approvals_pending_decide_by
    ON finding_status_approvals (decide_by)
    WHERE status = 'pending';

DROP INDEX IF EXISTS ux_finding_status_approvals_actor_pending;
