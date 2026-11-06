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

UPDATE findings
SET sla_status = finding_sla_status_for(status, sla_deadline, resolved_at, sla_status, false)
WHERE status = 'resolved' AND closure_reason = 'out_of_scope';
