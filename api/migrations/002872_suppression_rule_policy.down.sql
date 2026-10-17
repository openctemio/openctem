DELETE FROM suppression_rule_audit WHERE action = 'signed';
ALTER TABLE suppression_rule_audit DROP CONSTRAINT IF EXISTS chk_suppression_rule_audit_action;
ALTER TABLE suppression_rule_audit ADD CONSTRAINT chk_suppression_rule_audit_action
    CHECK (action IN ('created', 'approved', 'rejected', 'expired', 'deleted', 'updated'));
ALTER TABLE suppression_rules DROP CONSTRAINT IF EXISTS chk_suppression_rules_required;
ALTER TABLE suppression_rules DROP CONSTRAINT IF EXISTS chk_suppression_rules_tier;
ALTER TABLE suppression_rules
    DROP COLUMN IF EXISTS required_approvals,
    DROP COLUMN IF EXISTS tier,
    DROP COLUMN IF EXISTS reason_code;
