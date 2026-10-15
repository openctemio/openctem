-- Restores validated_fixed and not_observed as allowed statuses and the
-- functions that named them. Findings keep their current status (stale ones
-- become plain open findings: observation_state is dropped; the
-- validation_outcome stamps stay).
ALTER TABLE findings DROP CONSTRAINT chk_findings_status;
ALTER TABLE findings ADD CONSTRAINT chk_findings_status CHECK (status IN (
    'new', 'confirmed', 'in_progress', 'fix_applied', 'validated_fixed', 'not_observed',
    'resolved', 'false_positive', 'accepted', 'duplicate', 'draft', 'in_review'));

CREATE OR REPLACE FUNCTION is_open_finding_status(p_status text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE PARALLEL SAFE
AS $$
    SELECT p_status IN ('new', 'confirmed', 'in_progress', 'fix_applied', 'validated_fixed', 'not_observed')
$$;

CREATE OR REPLACE FUNCTION mark_finding_regression()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
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

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_observation_state;
ALTER TABLE findings DROP COLUMN observation_state;
