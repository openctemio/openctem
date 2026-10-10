-- Scope entry approvers (RFC-054 §7, amendment 2026-10-09): who may approve
-- a pending entry is named, reminders are rate-limited per entry, and an
-- owner with no other approver may approve their own entry with a fresh
-- authenticator code and a reason, recorded on the approval row.

ALTER TABLE scope_targets
    ADD COLUMN IF NOT EXISTS approval_reminded_at timestamptz NULL;

ALTER TABLE scope_target_approvals
    ADD COLUMN IF NOT EXISTS self_approved boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS reason        text    NOT NULL DEFAULT '',
    ADD CONSTRAINT chk_scope_target_approvals_reason CHECK (length(reason) <= 1000),
    ADD CONSTRAINT chk_scope_target_approvals_self_reason CHECK (NOT self_approved OR length(btrim(reason)) > 0);

COMMENT ON COLUMN scope_targets.approval_reminded_at IS 'When the approvers of a pending entry were last reminded (one reminder per hour)';
COMMENT ON COLUMN scope_target_approvals.self_approved IS 'An owner approved their own entry because no other approver existed (fresh TOTP, reason required)';
