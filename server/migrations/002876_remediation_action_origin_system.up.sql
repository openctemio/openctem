-- A remediation action created by the platform itself (a rotation task for a
-- secret a CI run found on a branch), next to the two origins a person
-- creates. Small table: the constraint swap takes no long lock.
ALTER TABLE remediation_actions
    DROP CONSTRAINT IF EXISTS chk_remediation_actions_origin,
    ADD CONSTRAINT chk_remediation_actions_origin CHECK (origin IN ('manual', 'suggestion', 'system'));
