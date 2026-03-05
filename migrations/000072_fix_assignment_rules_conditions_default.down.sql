-- Revert assignment_rules.conditions default back to array
ALTER TABLE assignment_rules ALTER COLUMN conditions SET DEFAULT '[]';
COMMENT ON COLUMN assignment_rules.conditions IS 'JSON array of conditions to match';
