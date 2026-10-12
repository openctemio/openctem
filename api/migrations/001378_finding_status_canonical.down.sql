-- Restores the previous CHECKs (aliases and `open` allowed again) and the
-- previous regression trigger. Rows mapped by the up migration keep their
-- canonical status: which ones were aliases is not recorded, and the
-- canonical statuses stay valid under the old CHECK.

CREATE OR REPLACE FUNCTION public.mark_finding_regression() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.status IN ('resolved', 'verified')
       AND NEW.status NOT IN ('resolved', 'verified', 'false_positive', 'accepted', 'accepted_risk', 'duplicate', 'not_observed')
    THEN
        NEW.is_regression    := TRUE;
        NEW.reopen_count     := COALESCE(OLD.reopen_count, 0) + 1;
        NEW.last_reopened_at := NOW();
    END IF;

    RETURN NEW;
END;
$$;

ALTER TABLE pentest_findings DROP CONSTRAINT IF EXISTS chk_pentest_findings_status;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_status;
ALTER TABLE findings ADD CONSTRAINT chk_findings_status CHECK (status IN (
    'new', 'open', 'confirmed', 'in_progress', 'fix_applied', 'validated_fixed', 'not_observed',
    'resolved', 'false_positive', 'accepted', 'duplicate',
    'draft', 'in_review', 'remediation', 'retest', 'verified', 'accepted_risk')) NOT VALID;
ALTER TABLE findings VALIDATE CONSTRAINT chk_findings_status;

COMMENT ON COLUMN findings.status IS 'Unified workflow: new → confirmed → in_progress → resolved (or false_positive, accepted, duplicate)';
