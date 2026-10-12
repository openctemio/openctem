-- Who reads a comment on a pentest finding: the campaign team only ('team',
-- the default) or the campaign's client too ('client'). Existing comments
-- stay team-only: until now they were written for the team. Other findings
-- have no client, so the column changes nothing for them.
ALTER TABLE finding_comments
    ADD COLUMN IF NOT EXISTS visibility VARCHAR(10) NOT NULL DEFAULT 'team';

ALTER TABLE finding_comments
    DROP CONSTRAINT IF EXISTS chk_finding_comments_visibility;
ALTER TABLE finding_comments
    ADD CONSTRAINT chk_finding_comments_visibility CHECK (visibility IN ('team', 'client'));

COMMENT ON COLUMN finding_comments.visibility IS
    'Pentest findings: team = campaign team only; client = the campaign client may read it too';
