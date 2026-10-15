-- A finding status request gets its own decide-by time, separate from the
-- end of the acceptance it asks for (expires_at). A pending request past
-- decide_by is expired by the hourly approval expiration job; before, a
-- pending request waited forever and its only deadline was the acceptance
-- end. See api/docs/architecture/finding-status-lifecycle.md (approvals).
--
-- Live impact: a nullable column with a volatile default (no rewrite: the
-- default applies to new rows only). The backfill of pending rows
-- is the next migration.

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS decide_by timestamptz;

-- Any writer that names no decide-by time (a platform actor's insert) gets
-- the default window (vulnerability.DefaultDecisionWindow), so no pending row
-- can wait forever and block the one-pending-request index.
ALTER TABLE finding_status_approvals
    ALTER COLUMN decide_by SET DEFAULT (now() + INTERVAL '14 days');

COMMENT ON COLUMN finding_status_approvals.decide_by IS
    'Latest moment a pending request can be decided; past it the request expires. Separate from expires_at (the acceptance end)';
