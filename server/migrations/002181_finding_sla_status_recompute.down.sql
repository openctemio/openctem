-- The repaired values stay (they are the correct ones).
DROP TRIGGER IF EXISTS trg_findings_recompute_sla_status ON findings;
DROP FUNCTION IF EXISTS recompute_finding_sla_status();
DROP FUNCTION IF EXISTS finding_sla_status_for(text, timestamptz, timestamptz, text, boolean);
