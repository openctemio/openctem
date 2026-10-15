-- A regression is a fix that evidence shows did not hold: a scan sees the
-- finding again, a retest fails, the vendor withdraws a fixed statement, an
-- indicator matches. A person moving a finding back from resolved (Undo, a
-- correction) is not one, so it no longer sets is_regression or counts in
-- reopen_count. The person paths mark their transaction with
--   SELECT set_config('openctem.person_move', 'on', true)

CREATE OR REPLACE FUNCTION mark_finding_regression()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Closed dispositions (false_positive, accepted, duplicate) are triage
    -- corrections, and not_observed is "not seen lately", not a fix that failed.
    IF OLD.status = 'resolved'
       AND NEW.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate', 'not_observed')
       AND COALESCE(current_setting('openctem.person_move', true), '') <> 'on'
    THEN
        NEW.is_regression    := TRUE;
        NEW.reopen_count     := COALESCE(OLD.reopen_count, 0) + 1;
        NEW.last_reopened_at := NOW();
    END IF;

    RETURN NEW;
END;
$$;
