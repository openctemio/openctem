-- A finding status approval can be requested by a platform actor instead of a
-- person: AI triage proposes a false positive for a medium or low finding it
-- is confident about (api/docs/architecture/finding-status-lifecycle.md,
-- "AI false-positive proposals"). requested_by stays NULL for such a request
-- and requested_by_actor names the actor. A person always approves: the
-- request is only ever pending until an approver decides.
--
-- At most one pending actor request per finding, so a re-run cannot pile up
-- proposals.
--
-- Live impact: a nullable column (no rewrite) and a partial index on rows that
-- do not exist yet.

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS requested_by_actor text;

ALTER TABLE finding_status_approvals
    DROP CONSTRAINT IF EXISTS chk_finding_status_approvals_actor;
ALTER TABLE finding_status_approvals
    ADD CONSTRAINT chk_finding_status_approvals_actor
    CHECK (requested_by_actor IS NULL OR (requested_by_actor IN ('ai_triage') AND requested_by IS NULL));

COMMENT ON COLUMN finding_status_approvals.requested_by_actor IS
    'Platform actor that requested the change (ai_triage) when no person did; NULL for a person''s request';

CREATE UNIQUE INDEX IF NOT EXISTS ux_finding_status_approvals_actor_pending
    ON finding_status_approvals (tenant_id, finding_id)
    WHERE status = 'pending' AND requested_by_actor IS NOT NULL;
