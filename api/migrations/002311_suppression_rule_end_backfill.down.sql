-- Gives back "no end" to the rules the backfill changed and nobody edited
-- since (an edit clears review_reason).
UPDATE suppression_rules
SET expires_at = NULL, review_flagged_at = NULL, review_reason = ''
WHERE review_reason = 'no_end_date';
