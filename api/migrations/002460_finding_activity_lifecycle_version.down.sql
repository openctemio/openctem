DROP TRIGGER IF EXISTS trg_finding_activities_lifecycle_version ON finding_activities;
DROP FUNCTION IF EXISTS finding_activity_lifecycle_version();
DROP FUNCTION IF EXISTS finding_lifecycle_version();
ALTER TABLE finding_activities DROP COLUMN IF EXISTS lifecycle_version;
