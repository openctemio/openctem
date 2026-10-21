DROP TRIGGER IF EXISTS trg_findings_sla_episode ON findings;
DROP FUNCTION IF EXISTS track_finding_sla_episode();
DROP FUNCTION IF EXISTS finding_sla_first_start(text, timestamptz, timestamptz);
ALTER TABLE findings
    DROP COLUMN IF EXISTS sla_at_risk_notified_at,
    DROP COLUMN IF EXISTS sla_breach_notified_at,
    DROP COLUMN IF EXISTS sla_started_at;
