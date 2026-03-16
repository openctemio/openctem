-- Fix assignment_rules.conditions default from JSON array '[]' to JSON object '{}'
-- The Go struct AssignmentConditions is a struct (object), not an array.

-- 1. Change the column default
ALTER TABLE assignment_rules ALTER COLUMN conditions SET DEFAULT '{}';

-- 2. Fix any existing rows that have an empty array '[]'
UPDATE assignment_rules SET conditions = '{}' WHERE conditions = '[]'::jsonb;

-- 3. Update column comment
COMMENT ON COLUMN assignment_rules.conditions IS 'JSON object of conditions to match (e.g. {"asset_type": ["host"], "finding_severity": ["critical"]})';
