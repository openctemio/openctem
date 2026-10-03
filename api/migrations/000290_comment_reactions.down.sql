BEGIN;

DROP TRIGGER IF EXISTS trg_comment_reaction_tenant_match ON comment_reactions;
DROP FUNCTION IF EXISTS comment_reaction_tenant_matches_comment();
DROP TABLE IF EXISTS comment_reactions;

ALTER TABLE finding_comments DROP COLUMN IF EXISTS is_internal;

COMMIT;
