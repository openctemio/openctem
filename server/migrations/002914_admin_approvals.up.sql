-- Four-eyes approvals for the platform console's catastrophic actions
-- (docs/architecture/platform-console.md, "Four-eyes approvals").
-- A platform table: no tenant data. One row per request; decisions and use are
-- recorded on the row, and the admin audit log keeps the history.
CREATE TABLE IF NOT EXISTS admin_approvals (
    id            UUID PRIMARY KEY,
    action        VARCHAR(64)  NOT NULL,
    target        VARCHAR(320) NOT NULL,
    target_label  VARCHAR(320) NOT NULL DEFAULT '',
    reason        TEXT         NOT NULL,
    requested_by  UUID         NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    requested_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ  NOT NULL,
    decided_by    UUID         REFERENCES admin_users(id) ON DELETE SET NULL,
    decided_at    TIMESTAMPTZ,
    decision      VARCHAR(16),
    decision_note TEXT         NOT NULL DEFAULT '',
    consumed_at   TIMESTAMPTZ,
    CONSTRAINT admin_approvals_decision_check
        CHECK (decision IS NULL OR decision IN ('approved', 'rejected', 'canceled')),
    -- Nobody approves or rejects their own request (canceling is the
    -- requester's own act).
    CONSTRAINT admin_approvals_not_self
        CHECK (decision IS NULL OR decision = 'canceled' OR decided_by IS DISTINCT FROM requested_by),
    -- Only an approved request can be used.
    CONSTRAINT admin_approvals_consumed_approved
        CHECK (consumed_at IS NULL OR decision = 'approved'),
    CONSTRAINT admin_approvals_reason_present CHECK (length(btrim(reason)) > 0)
);

CREATE INDEX IF NOT EXISTS idx_admin_approvals_binding
    ON admin_approvals (requested_by, action, target)
    WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_admin_approvals_requested_at
    ON admin_approvals (requested_at DESC);

COMMENT ON TABLE admin_approvals IS
    'Second super admin approvals for catastrophic console actions: bound to requester, action and target; single use; expiring.';
