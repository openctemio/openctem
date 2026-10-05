-- 000640: the not_observed finding status (research 18, owner decision O2).
--
-- not_observed = recent scans no longer report the finding, but nothing proves
-- the check ran against it. It is stale, NOT fixed: never counted as fixed, and
-- its SLA keeps running. Only the platform sets it (feature-branch expiry today).
--
-- 1. findings.status gets a CHECK constraint naming every status the API knows,
--    not_observed included. There was none since 000095 dropped the old one, so
--    any string could be stored. Added NOT VALID (no table scan under the
--    ACCESS EXCLUSIVE lock), then validated (SHARE UPDATE EXCLUSIVE: reads and
--    writes continue).
-- 2. Rows closed by feature-branch expiry (resolution 'branch_expired', the only
--    writer of that value) move from resolved to not_observed. Provenance is
--    certain; no other resolved row is touched.
-- 3. The regression trigger does not count resolved -> not_observed (or the
--    accepted disposition) as "we fixed it and it came back".

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_status;
-- 'open' is a legacy spelling of new that older rows and queries still use
-- (the open-status SQL lists accept it); it stays allowed.
ALTER TABLE findings ADD CONSTRAINT chk_findings_status CHECK (status IN (
    'new', 'open', 'confirmed', 'in_progress', 'fix_applied', 'validated_fixed', 'not_observed',
    'resolved', 'false_positive', 'accepted', 'duplicate',
    'draft', 'in_review', 'remediation', 'retest', 'verified', 'accepted_risk'
)) NOT VALID;

CREATE OR REPLACE FUNCTION mark_finding_regression()
RETURNS TRIGGER AS $$
BEGIN
    -- Only "we fixed it and it came back" counts. Closed dispositions
    -- (false_positive, accepted, accepted_risk, duplicate) are triage
    -- corrections, and not_observed is "not seen lately", not a fix that failed.
    IF OLD.status IN ('resolved', 'verified')
       AND NEW.status NOT IN ('resolved', 'verified', 'false_positive', 'accepted', 'accepted_risk', 'duplicate', 'not_observed')
    THEN
        NEW.is_regression    := TRUE;
        NEW.reopen_count     := COALESCE(OLD.reopen_count, 0) + 1;
        NEW.last_reopened_at := NOW();
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

UPDATE findings
SET status = 'not_observed',
    resolution_method = NULL,
    resolved_at = NULL,
    resolved_by = NULL,
    updated_at = NOW()
WHERE status = 'resolved'
  AND resolution = 'branch_expired';

ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_status;
