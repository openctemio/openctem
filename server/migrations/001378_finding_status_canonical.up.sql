-- One finding status set for every source. The pentest aliases are folded
-- into the statuses every finding uses, how a finding was closed moves to its
-- resolution, and `open` (never a status) goes:
--   remediation   -> in_progress
--   retest        -> fix_applied
--   verified      -> resolved (resolution_method retest_verified)
--   accepted_risk -> accepted
--   open          -> new
-- Then findings.status and pentest_findings.status get a CHECK on exactly the
-- Go list (vulnerability.AllFindingStatuses; pentest findings never use the
-- scanner-only states). Idempotent: a second run maps nothing.

-- The regression trigger does not fire on these (verified -> resolved stays
-- closed; the others do not start from resolved).
UPDATE findings SET status = 'in_progress' WHERE status = 'remediation';
UPDATE findings SET status = 'fix_applied' WHERE status = 'retest';
UPDATE findings
   SET status = 'resolved',
       resolution_method = COALESCE(resolution_method, 'retest_verified'),
       resolution = COALESCE(resolution, 'verified by retest'),
       resolved_at = COALESCE(resolved_at, verified_at, updated_at)
 WHERE status = 'verified';
UPDATE findings SET status = 'accepted' WHERE status = 'accepted_risk';
UPDATE findings SET status = 'new' WHERE status = 'open';

ALTER TABLE findings ENABLE TRIGGER USER;

UPDATE pentest_findings SET status = CASE status
    WHEN 'remediation' THEN 'in_progress'
    WHEN 'retest' THEN 'fix_applied'
    WHEN 'verified' THEN 'resolved'
    WHEN 'accepted_risk' THEN 'accepted'
    ELSE status END
 WHERE status IN ('remediation', 'retest', 'verified', 'accepted_risk');

UPDATE finding_status_approvals SET requested_status = 'accepted' WHERE requested_status = 'accepted_risk';

UPDATE finding_retests SET prior_status = CASE prior_status
    WHEN 'remediation' THEN 'in_progress' WHEN 'retest' THEN 'fix_applied'
    WHEN 'verified' THEN 'resolved' WHEN 'accepted_risk' THEN 'accepted'
    WHEN 'open' THEN 'new' ELSE prior_status END
 WHERE prior_status IN ('remediation', 'retest', 'verified', 'accepted_risk', 'open');
UPDATE finding_retests SET result_status = CASE result_status
    WHEN 'remediation' THEN 'in_progress' WHEN 'retest' THEN 'fix_applied'
    WHEN 'verified' THEN 'resolved' WHEN 'accepted_risk' THEN 'accepted'
    WHEN 'open' THEN 'new' ELSE result_status END
 WHERE result_status IN ('remediation', 'retest', 'verified', 'accepted_risk', 'open');

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_status;
ALTER TABLE findings ADD CONSTRAINT chk_findings_status CHECK (status IN (
    'new', 'confirmed', 'in_progress', 'fix_applied', 'validated_fixed', 'not_observed',
    'resolved', 'false_positive', 'accepted', 'duplicate', 'draft', 'in_review')) NOT VALID;
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_status;

ALTER TABLE pentest_findings DROP CONSTRAINT IF EXISTS chk_pentest_findings_status;
ALTER TABLE pentest_findings ADD CONSTRAINT chk_pentest_findings_status CHECK (status IN (
    'draft', 'in_review', 'confirmed', 'in_progress', 'fix_applied', 'resolved',
    'false_positive', 'accepted')) NOT VALID;
ALTER TABLE pentest_findings VALIDATE CONSTRAINT chk_pentest_findings_status;

-- A regression is "fixed, and it came back": resolved -> an open status.
CREATE OR REPLACE FUNCTION public.mark_finding_regression() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Closed dispositions (false_positive, accepted, duplicate) are triage
    -- corrections, and not_observed is "not seen lately", not a fix that failed.
    IF OLD.status = 'resolved'
       AND NEW.status NOT IN ('resolved', 'false_positive', 'accepted', 'duplicate', 'not_observed')
    THEN
        NEW.is_regression    := TRUE;
        NEW.reopen_count     := COALESCE(OLD.reopen_count, 0) + 1;
        NEW.last_reopened_at := NOW();
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON COLUMN findings.status IS 'Finding lifecycle (pkg/domain/vulnerability): new, confirmed, in_progress, fix_applied, validated_fixed, not_observed, resolved, false_positive, accepted, duplicate; pentest pre-publication draft, in_review. How a finding was closed is resolution_method.';
