-- SLA clock start and notify-on-state (api/docs/architecture/sla-escalation.md).
--
-- sla_started_at is when the current SLA clock started: first detection for
-- the first deadline (pentest: publication), the moment of a regression
-- restart, the end of a risk acceptance, a false-positive withdrawal or the
-- promotion of a branch-only finding. The at-risk warning is measured from it,
-- so a clock that starts again does not warn at once.
--
-- sla_breach_notified_at / sla_at_risk_notified_at record that the escalation
-- job announced the current episode. The job selects on them, so a breach is
-- announced whoever set sla_status to overdue (a reopen, an un-suppression, a
-- status change after the deadline), once per episode. A new clock or a reopen
-- starts a new episode and clears both.
--
-- Live impact: three nullable columns (no rewrite); one backfill UPDATE over
-- findings with a deadline, with the updated_at and row_version triggers off
-- so the backfill does not show as an edit. Rows already overdue or warning
-- count as announced, so the deploy sends nothing.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS sla_started_at timestamptz,
    ADD COLUMN IF NOT EXISTS sla_breach_notified_at timestamptz,
    ADD COLUMN IF NOT EXISTS sla_at_risk_notified_at timestamptz;

COMMENT ON COLUMN findings.sla_started_at IS
    'When the current SLA clock started (first detection, pentest publication, or the restart that set the deadline)';
COMMENT ON COLUMN findings.sla_breach_notified_at IS
    'When the escalation job announced the breach of the current SLA episode; NULL = not announced';
COMMENT ON COLUMN findings.sla_at_risk_notified_at IS
    'When the escalation job announced that the current SLA episode is at risk; NULL = not announced';

ALTER TABLE findings DISABLE TRIGGER trigger_findings_updated_at;
ALTER TABLE findings DISABLE TRIGGER trg_findings_row_version;

UPDATE findings SET
    sla_started_at = COALESCE(last_reopened_at, first_detected_at, created_at),
    sla_breach_notified_at = CASE WHEN sla_status IN ('overdue', 'exceeded') THEN NOW() END,
    sla_at_risk_notified_at = CASE WHEN sla_status IN ('warning', 'overdue', 'exceeded') THEN NOW() END
WHERE sla_deadline IS NOT NULL;

ALTER TABLE findings ENABLE TRIGGER trigger_findings_updated_at;
ALTER TABLE findings ENABLE TRIGGER trg_findings_row_version;

-- The start of a first deadline: first detection, except a pentest finding,
-- whose deadline counts from its publication.
CREATE OR REPLACE FUNCTION finding_sla_first_start(p_source text, p_first_detected_at timestamptz, p_created_at timestamptz)
RETURNS timestamptz
LANGUAGE sql STABLE
AS $$
    SELECT CASE WHEN p_source = 'pentest' THEN NOW() ELSE COALESCE(p_first_detected_at, p_created_at, NOW()) END
$$;

COMMENT ON FUNCTION finding_sla_first_start(text, timestamptz, timestamptz) IS
    'Start of a finding''s first SLA clock: first detection, or now for a pentest finding (counted from publication)';

-- Keeps sla_started_at and the notification episode right for every writer.
-- A writer that starts a new clock on purpose sets sla_started_at itself
-- (regression restart, acceptance expiry, false-positive withdrawal); this
-- fills it for a first deadline and for the promotion of a branch-only
-- finding, and clears the notified-at columns when a new clock starts or a
-- closed finding opens again. It runs after trg_findings_sla_deadline_guard
-- (BEFORE triggers fire in name order), so it sees the deadline that is kept.
CREATE OR REPLACE FUNCTION track_finding_sla_episode() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.sla_deadline IS NOT NULL AND NEW.sla_started_at IS NULL THEN
            NEW.sla_started_at := finding_sla_first_start(NEW.source, NEW.first_detected_at, NEW.created_at);
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.sla_started_at IS NOT DISTINCT FROM OLD.sla_started_at AND NEW.sla_deadline IS NOT NULL THEN
        IF OLD.sla_deadline IS NULL THEN
            NEW.sla_started_at := finding_sla_first_start(NEW.source, NEW.first_detected_at, NEW.created_at);
        ELSIF OLD.branch_only AND NOT NEW.branch_only THEN
            NEW.sla_started_at := NOW();
        END IF;
    END IF;

    IF NEW.sla_started_at IS DISTINCT FROM OLD.sla_started_at
       OR (NOT is_open_finding_status(OLD.status) AND is_open_finding_status(NEW.status)) THEN
        NEW.sla_breach_notified_at := NULL;
        NEW.sla_at_risk_notified_at := NULL;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION track_finding_sla_episode() IS
    'Row trigger: fills findings.sla_started_at for a first deadline or a branch promotion, and clears the SLA notified-at columns when a new clock starts or a closed finding reopens';

DROP TRIGGER IF EXISTS trg_findings_sla_episode ON findings;
CREATE TRIGGER trg_findings_sla_episode
    BEFORE INSERT OR UPDATE OF status, sla_deadline, sla_started_at, branch_only ON findings
    FOR EACH ROW
    EXECUTE FUNCTION track_finding_sla_episode();
