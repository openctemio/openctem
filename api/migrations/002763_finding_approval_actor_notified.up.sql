-- When the approvers were told about a pending request a platform actor
-- made (VEX statements in a scan report). The table itself is the outbox:
-- ingest only writes the request; a background job claims the rows nobody was
-- told about yet and sends one batched notice per tenant and approver, so a
-- large report never slows the ingest.
--
-- Live impact: a nullable column (no rewrite) on a small table, and a
-- partial index on rows that wait for a notice.

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS approvers_notified_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_finding_status_approvals_actor_unnotified
    ON finding_status_approvals (created_at)
    WHERE status = 'pending' AND requested_by_actor IS NOT NULL AND approvers_notified_at IS NULL;

COMMENT ON COLUMN finding_status_approvals.approvers_notified_at IS
    'When the approvers were told about a request a platform actor made (the notice outbox); NULL: not yet';
