DROP TRIGGER IF EXISTS trg_findings_sla_deadline_guard ON findings;
DROP FUNCTION IF EXISTS guard_sla_deadline_tighten_only();
