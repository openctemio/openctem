DROP INDEX IF EXISTS idx_business_units_criticality;
DROP INDEX IF EXISTS idx_business_units_parent;
ALTER TABLE business_units
    DROP CONSTRAINT IF EXISTS business_units_no_self_parent;
ALTER TABLE business_units
    DROP COLUMN IF EXISTS parent_id,
    DROP COLUMN IF EXISTS risk_tolerance,
    DROP COLUMN IF EXISTS criticality;
