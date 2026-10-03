ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_type_details_shape;
ALTER TABLE findings DROP COLUMN IF EXISTS type_details;
