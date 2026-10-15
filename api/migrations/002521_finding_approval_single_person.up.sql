-- A false positive one person decided alone because the organization's
-- false-positive approval setting does not require a second person for that
-- finding (settings.finding_approvals.fp_approval: high_and_above or off).
-- The request row is written already approved with single_person = true, so
-- every list, the audit trail and the material-change review flag (next
-- migration) can tell it from a four-eyes decision.
--
-- Live impact: a boolean with a constant default (no rewrite since
-- PostgreSQL 11) on a small table.

ALTER TABLE finding_status_approvals
    ADD COLUMN IF NOT EXISTS single_person boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN finding_status_approvals.single_person IS
    'Decided by one person under the organization''s false-positive approval setting (no second approver)';
