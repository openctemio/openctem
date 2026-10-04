-- Revert 000505. not_observed rows go back to how feature-branch expiry wrote
-- them (resolved / branch_expired) when that is why they are not observed;
-- any other not_observed row (none are written yet) becomes confirmed, an open
-- state, so nothing is silently counted as fixed.
UPDATE findings
SET status = 'resolved',
    resolved_at = COALESCE(resolved_at, updated_at),
    updated_at = NOW()
WHERE status = 'not_observed'
  AND resolution = 'branch_expired';

UPDATE findings
SET status = 'confirmed',
    updated_at = NOW()
WHERE status = 'not_observed';

CREATE OR REPLACE FUNCTION mark_finding_regression()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IN ('resolved', 'verified')
       AND NEW.status NOT IN ('resolved', 'verified', 'false_positive', 'accepted_risk', 'duplicate')
    THEN
        NEW.is_regression    := TRUE;
        NEW.reopen_count     := COALESCE(OLD.reopen_count, 0) + 1;
        NEW.last_reopened_at := NOW();
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_status;
