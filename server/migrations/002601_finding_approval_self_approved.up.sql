-- A finding request the sole member of an organization approved
-- themselves (owner, fresh authenticator code, a reason): marked so every
-- list, the audit trail and later reviews show it was not four-eyes.
--
-- Live impact: a boolean with a constant default (no rewrite since
-- PostgreSQL 11) and a nullable text column, on a small table.

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS self_approved boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS self_approval_reason text;

COMMENT ON COLUMN finding_status_approvals.self_approved IS
    'Approved by its own requester, the sole active member of the organization (fresh authenticator code + reason)';
