ALTER TABLE scan_runs DROP COLUMN IF EXISTS spec_digest;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS scan_workflow_version;
DROP TABLE IF EXISTS scan_workflow_versions;
