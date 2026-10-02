BEGIN;

DROP TRIGGER IF EXISTS trg_finding_comment_tenant_match ON finding_comments;
DROP TRIGGER IF EXISTS trg_finding_activity_tenant_match ON finding_activities;
DROP FUNCTION IF EXISTS finding_comment_tenant_matches_finding();
DROP FUNCTION IF EXISTS finding_activity_tenant_matches_finding();

DROP INDEX IF EXISTS idx_finding_comments_tenant_id;
DROP INDEX IF EXISTS idx_finding_activities_tenant_id;

ALTER TABLE finding_comments   DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE finding_activities DROP COLUMN IF EXISTS tenant_id;

COMMIT;
