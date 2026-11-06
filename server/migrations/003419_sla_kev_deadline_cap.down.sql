-- sla_kev_deadline_cap (down)
-- Restores the trigger functions of 002221 and 002243, then drops the columns.

CREATE OR REPLACE FUNCTION record_sla_deadline_tightened() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_reason text;
BEGIN
    v_reason := CASE
        -- P0 sorts before P3: a lower class string is a higher priority.
        WHEN NEW.priority_class IS NOT NULL
             AND (OLD.priority_class IS NULL OR NEW.priority_class < OLD.priority_class) THEN 'priority_raised'
        ELSE 'sla_policy_changed'
    END;
    INSERT INTO finding_activities (tenant_id, finding_id, activity_type, actor_type, actor_name, changes, source)
    VALUES (
        NEW.tenant_id, NEW.id, 'sla_deadline_tightened', 'system', 'system: SLA', jsonb_build_object(
            'previous_sla_deadline', to_char(OLD.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'sla_deadline', to_char(NEW.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'previous_priority_class', OLD.priority_class,
            'priority_class', NEW.priority_class,
            'reason', v_reason,
            'content', CASE
                WHEN v_reason = 'priority_raised' THEN format('SLA deadline moved earlier, from %s to %s, because the priority rose from %s to %s',
                    to_char(OLD.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI "UTC"'),
                    to_char(NEW.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI "UTC"'),
                    COALESCE(OLD.priority_class, 'none'), COALESCE(NEW.priority_class, 'none'))
                ELSE format('SLA deadline moved earlier, from %s to %s, because the SLA policy changed',
                    to_char(OLD.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI "UTC"'),
                    to_char(NEW.sla_deadline AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI "UTC"'))
            END),
        'auto');
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION guard_sla_deadline_tighten_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF COALESCE(current_setting('openctem.sla_restart', true), '') = 'on' THEN
        RETURN NEW;
    END IF;
    NEW.sla_deadline := OLD.sla_deadline;
    -- The status the kept deadline gives (trg_findings_recompute_sla_status
    -- ran first, on the refused one).
    NEW.sla_status := finding_sla_status_for(NEW.status, OLD.sla_deadline, NEW.resolved_at, OLD.sla_status, true);
    RETURN NEW;
END;
$$;

ALTER TABLE findings DROP COLUMN IF EXISTS sla_kev_capped;
ALTER TABLE sla_policies DROP CONSTRAINT IF EXISTS chk_sla_policies_kev_cap_days;
ALTER TABLE sla_policies DROP COLUMN IF EXISTS kev_cap_days;
