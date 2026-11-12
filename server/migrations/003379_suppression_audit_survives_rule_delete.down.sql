-- Rows whose rule is gone cannot satisfy NOT NULL; they are dropped, as the
-- old cascade did.
DELETE FROM suppression_rule_audit WHERE suppression_rule_id IS NULL;
ALTER TABLE suppression_rule_audit DROP CONSTRAINT IF EXISTS suppression_rule_audit_suppression_rule_id_fkey;
ALTER TABLE suppression_rule_audit
    ADD CONSTRAINT suppression_rule_audit_suppression_rule_id_fkey
    FOREIGN KEY (suppression_rule_id) REFERENCES suppression_rules(id) ON DELETE CASCADE NOT VALID;
ALTER TABLE suppression_rule_audit VALIDATE CONSTRAINT suppression_rule_audit_suppression_rule_id_fkey;
ALTER TABLE suppression_rule_audit ALTER COLUMN suppression_rule_id SET NOT NULL;
