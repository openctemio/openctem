-- Validates the constraints suppression_rule_policy added NOT VALID (SHARE
-- UPDATE EXCLUSIVE: reads and writes continue).
ALTER TABLE suppression_rules VALIDATE CONSTRAINT chk_suppression_rules_tier;
ALTER TABLE suppression_rules VALIDATE CONSTRAINT chk_suppression_rules_required;
ALTER TABLE suppression_rule_audit VALIDATE CONSTRAINT chk_suppression_rule_audit_action;
