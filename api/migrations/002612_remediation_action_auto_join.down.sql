ALTER TABLE remediation_actions
    DROP CONSTRAINT IF EXISTS chk_remediation_actions_auto_join_kind,
    DROP CONSTRAINT IF EXISTS fk_remediation_actions_auto_join_by,
    DROP COLUMN IF EXISTS auto_join_at,
    DROP COLUMN IF EXISTS auto_join_by,
    DROP COLUMN IF EXISTS auto_join;
