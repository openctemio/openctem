ALTER TABLE finding_comments DROP CONSTRAINT IF EXISTS chk_finding_comments_visibility;
ALTER TABLE finding_comments DROP COLUMN IF EXISTS visibility;
