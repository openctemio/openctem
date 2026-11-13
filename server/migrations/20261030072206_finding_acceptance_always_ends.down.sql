-- Drops the default-end trigger. Ends already written stay (an accepted risk
-- always ends; the CI gate does not honor an acceptance without one).
DROP TRIGGER IF EXISTS trg_findings_default_acceptance_end ON findings;
DROP FUNCTION IF EXISTS default_finding_acceptance_end();
