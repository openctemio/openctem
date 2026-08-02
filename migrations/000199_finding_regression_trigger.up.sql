-- Regression tracking has been read-only since migration 000152.
--
-- 000152 added findings.is_regression / reopen_count / last_reopened_at and the
-- finding_regression_events table. The executive summary reads them
-- (dashboard_repository.go "regressions" CTE) and reports "N regressions
-- recorded" plus a regression rate in the UI, the CSV export and the emailed
-- digest. Nothing has ever written them. On the reference database: 0 of 188
-- findings flagged, 0 with last_reopened_at. Every one of those surfaces has
-- been stating "0 regressions / 0.0%" as fact.
--
-- The mark belongs in a trigger rather than in Go because reopens arrive by two
-- routes that share no code: FindingRepository.AutoReopenByFingerprintsBatch is
-- a set-based UPDATE that never loads the entity, while the IOC runtime-match
-- reopen goes through Finding.UpdateStatus + a full-row Update. Marking it in
-- either one alone leaves the other silently uncounted, and marking it in the
-- entity risks the opposite failure: a later load-and-save round trip through a
-- SELECT list that does not carry these columns would write the flag back off.
-- A BEFORE UPDATE trigger sees every writer, present and future, and cannot be
-- clobbered.
--
-- This mirrors trg_update_branch_finding_counts_update, which already maintains
-- derived counters off findings.status the same way.

CREATE OR REPLACE FUNCTION mark_finding_regression()
RETURNS TRIGGER AS $$
BEGIN
    -- Only "we fixed it and it came back" counts.
    --
    -- resolved and verified are the two statuses the executive summary's
    -- denominator (total_resolved) is built from, so the numerator has to be
    -- built from the same two or the rate compares unlike things.
    --
    -- The other closed statuses are deliberately excluded: reopening a
    -- false_positive, accepted_risk or duplicate is a triage correction, not a
    -- fix that failed, and counting it would inflate the regression rate with
    -- reclassifications.
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

-- BEFORE, so the columns are set in the same write rather than costing a second
-- UPDATE. WHEN () keeps it off the hot path: findings are updated constantly by
-- rescans and enrichment, and only a genuine status change can be a regression.
DROP TRIGGER IF EXISTS trg_findings_mark_regression ON findings;
CREATE TRIGGER trg_findings_mark_regression
    BEFORE UPDATE OF status ON findings
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION mark_finding_regression();

-- No backfill. Reopen history was never recorded, so there is nothing to
-- reconstruct it from — inventing one would produce a number that looks
-- authoritative and is not, which is the defect this migration exists to fix.
-- The counter starts from now.
