-- sla_status follows every status change, whatever writes it.
--
--   no deadline                          -> not_applicable
--   false_positive / accepted / duplicate -> not_applicable (a decision not to
--                                            fix leaves the SLA)
--   resolved                             -> on_track when fixed by the deadline
--                                            (met), else exceeded (missed); the
--                                            clock stops at the verified fix
--   open, past the deadline              -> overdue
--   open, otherwise                      -> on_track; the SLA escalation job is
--                                            the one place that applies the
--                                            policy's warning threshold, and a
--                                            move between open statuses keeps a
--                                            warning it set
--   pentest draft / in_review            -> unchanged
--
-- Before, sla_status was only computed when a deadline was set, so closed
-- findings kept "overdue" or "exceeded" and dispositions showed "exceeded".

CREATE OR REPLACE FUNCTION finding_sla_status_for(
    p_status text, p_deadline timestamptz, p_resolved_at timestamptz, p_current text, p_was_open boolean
) RETURNS text
LANGUAGE sql STABLE
AS $$
    SELECT CASE
        WHEN p_deadline IS NULL THEN 'not_applicable'
        WHEN p_status IN ('false_positive', 'accepted', 'duplicate') THEN 'not_applicable'
        WHEN p_status = 'resolved' THEN
            CASE WHEN COALESCE(p_resolved_at, NOW()) <= p_deadline THEN 'on_track' ELSE 'exceeded' END
        WHEN is_open_finding_status(p_status) THEN
            CASE
                WHEN p_deadline < NOW() THEN 'overdue'
                WHEN p_was_open AND p_current = 'warning' THEN 'warning'
                ELSE 'on_track'
            END
        ELSE p_current
    END
$$;

COMMENT ON FUNCTION finding_sla_status_for(text, timestamptz, timestamptz, text, boolean) IS
    'The sla_status a finding has for its status, deadline and close time (one definition, used by the recompute trigger)';

CREATE OR REPLACE FUNCTION recompute_finding_sla_status()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS NOT DISTINCT FROM OLD.status
       AND NEW.sla_deadline IS NOT DISTINCT FROM OLD.sla_deadline THEN
        RETURN NEW;
    END IF;
    NEW.sla_status := finding_sla_status_for(
        NEW.status, NEW.sla_deadline, NEW.resolved_at, NEW.sla_status,
        is_open_finding_status(OLD.status) AND NEW.sla_deadline IS NOT DISTINCT FROM OLD.sla_deadline);
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION recompute_finding_sla_status() IS
    'Recomputes findings.sla_status on every status or deadline change';

CREATE TRIGGER trg_findings_recompute_sla_status
    BEFORE UPDATE OF status, sla_deadline ON findings
    FOR EACH ROW
    EXECUTE FUNCTION recompute_finding_sla_status();

-- One-time repair of stale values: a closed finding still "overdue", a
-- disposition "exceeded", an open finding past its deadline not "overdue".
UPDATE findings
SET sla_status = finding_sla_status_for(status, sla_deadline, resolved_at, sla_status, is_open_finding_status(status))
WHERE sla_status IS DISTINCT FROM finding_sla_status_for(status, sla_deadline, resolved_at, sla_status, is_open_finding_status(status));
