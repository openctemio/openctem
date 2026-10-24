ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_identity_fields;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_identity_algo;
ALTER TABLE findings DROP COLUMN IF EXISTS identity_fields;
ALTER TABLE findings DROP COLUMN IF EXISTS identity_algo;
