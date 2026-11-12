-- The audit row that records who deleted a suppression rule was erased by the
-- cascade of the very delete it describes. The rule id is now nullable with
-- ON DELETE SET NULL; the deleting transaction also keeps the id in details.
ALTER TABLE suppression_rule_audit ALTER COLUMN suppression_rule_id DROP NOT NULL;
ALTER TABLE suppression_rule_audit DROP CONSTRAINT IF EXISTS suppression_rule_audit_suppression_rule_id_fkey;
ALTER TABLE suppression_rule_audit
    ADD CONSTRAINT suppression_rule_audit_suppression_rule_id_fkey
    FOREIGN KEY (suppression_rule_id) REFERENCES suppression_rules(id) ON DELETE SET NULL NOT VALID;
ALTER TABLE suppression_rule_audit VALIDATE CONSTRAINT suppression_rule_audit_suppression_rule_id_fkey;
