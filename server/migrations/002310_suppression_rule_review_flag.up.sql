-- Suppression rules always end (research 159 P0-7). This adds the review
-- flag the platform sets on a rule it gave an end it did not have; the next
-- migration fills it, and gives expires_at a default end (90 days) for
-- writers that name none. Nullable / constant-default columns and a column
-- default are metadata-only: no table rewrite.
ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS review_flagged_at TIMESTAMPTZ;
ALTER TABLE suppression_rules ADD COLUMN IF NOT EXISTS review_reason TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN suppression_rules.review_flagged_at IS
    'Set when the platform gave the rule an end it did not have; cleared when a person edits the rule.';
COMMENT ON COLUMN suppression_rules.review_reason IS
    'Why the rule is flagged for review (no_end_date); empty when not flagged.';

ALTER TABLE suppression_rules ALTER COLUMN expires_at SET DEFAULT (now() + interval '90 days');
