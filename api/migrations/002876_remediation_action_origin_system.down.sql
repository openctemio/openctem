UPDATE remediation_actions SET origin = 'manual' WHERE origin = 'system';
ALTER TABLE remediation_actions
    DROP CONSTRAINT IF EXISTS chk_remediation_actions_origin,
    ADD CONSTRAINT chk_remediation_actions_origin CHECK (origin IN ('manual', 'suggestion'));
