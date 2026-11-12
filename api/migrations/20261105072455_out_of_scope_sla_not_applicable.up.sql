-- A finding closed because its asset was marked out of scope (not ours or
-- retired, closure reason out_of_scope) leaves the SLA like a disposition:
-- sla_status not_applicable. Before, the close counted as an SLA met (closed
-- by the deadline) or missed (after it), so marking assets out of scope
-- changed SLA compliance. Reopening it (re-include) recomputes from the
-- deadline it kept, so excluding and re-including never resets a clock.

CREATE OR REPLACE FUNCTION recompute_finding_sla_status()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS NOT DISTINCT FROM OLD.status
       AND NEW.sla_deadline IS NOT DISTINCT FROM OLD.sla_deadline THEN
        RETURN NEW;
    END IF;
    IF NEW.status = 'resolved' AND NEW.closure_reason = 'out_of_scope' THEN
        NEW.sla_status := 'not_applicable';
        RETURN NEW;
    END IF;
    NEW.sla_status := finding_sla_status_for(
        NEW.status, NEW.sla_deadline, NEW.resolved_at, NEW.sla_status,
        is_open_finding_status(OLD.status) AND NEW.sla_deadline IS NOT DISTINCT FROM OLD.sla_deadline);
    RETURN NEW;
END;
$$;

-- Findings already closed as out of scope (a plain UPDATE of sla_status:
-- the trigger fires only on status or deadline changes).
UPDATE findings SET sla_status = 'not_applicable'
WHERE status = 'resolved' AND closure_reason = 'out_of_scope'
  AND sla_status IS DISTINCT FROM 'not_applicable';
