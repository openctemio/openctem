-- Auto-join rule per accepted remediation action
-- (docs/rfcs/RFC-098-remediation-tasks.md §6): when a person turns it on,
-- new findings with the action's exact key join the live task of their
-- owner (open or in progress) without a suggestion. Deterministic keys only
-- (upgrade, rotate); off by default; it never changes a finding's status.
--
-- Live impact: three nullable/defaulted columns on a new, small table.

ALTER TABLE remediation_actions
    ADD COLUMN IF NOT EXISTS auto_join    boolean     NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS auto_join_by uuid,
    ADD COLUMN IF NOT EXISTS auto_join_at timestamptz;

ALTER TABLE remediation_actions
    ADD CONSTRAINT fk_remediation_actions_auto_join_by FOREIGN KEY (auto_join_by)
        REFERENCES users (id) ON DELETE SET NULL,
    ADD CONSTRAINT chk_remediation_actions_auto_join_kind CHECK (NOT auto_join OR kind IN ('upgrade', 'rotate'));

CREATE INDEX IF NOT EXISTS idx_remediation_actions_auto_join_by
    ON remediation_actions (auto_join_by) WHERE auto_join_by IS NOT NULL;

COMMENT ON COLUMN remediation_actions.auto_join IS
    'A person opted in: new findings with this exact key join the owner''s live task (open or in progress) without a suggestion.';
