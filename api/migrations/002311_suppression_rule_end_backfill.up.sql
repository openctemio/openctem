-- Every suppression rule ends (research 159 P0-7): a rule without an end
-- hid findings from the backlog and the CI gate for good. Rules made before
-- the end was required get the default end (90 days from now) and, when they
-- still matter (pending or approved), the review flag so an approver looks
-- at them again. suppression_rules is a small per-tenant table (a handful of
-- rows per organization), so one statement suffices; it touches only rows
-- without an end.
UPDATE suppression_rules
SET expires_at        = now() + interval '90 days',
    review_reason     = 'no_end_date',
    review_flagged_at = CASE WHEN status IN ('pending', 'approved') THEN now() END,
    updated_at        = now()
WHERE expires_at IS NULL;
