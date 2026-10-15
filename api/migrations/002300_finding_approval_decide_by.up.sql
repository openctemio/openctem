-- A finding status request gets its own decide-by time, separate from the
-- end of the acceptance it asks for (expires_at). A pending request past
-- decide_by is expired by the hourly approval expiration job; before, a
-- pending request waited forever and its only deadline was the acceptance
-- end. See api/docs/architecture/finding-status-lifecycle.md (approvals).
--
-- Live impact: a nullable column (no rewrite). The backfill of pending rows
-- is the next migration.

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS decide_by timestamptz;

COMMENT ON COLUMN finding_status_approvals.decide_by IS
    'Latest moment a pending request can be decided; past it the request expires. Separate from expires_at (the acceptance end)';
