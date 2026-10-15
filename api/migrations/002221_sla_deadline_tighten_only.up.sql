-- SLA deadlines only tighten automatically
-- (api/docs/architecture/scoring-versions.md, "SLA on a priority change").
--
-- When an open finding's priority rises, or the SLA policy gets shorter, the
-- deadline becomes min(old deadline, change time + new SLA). A priority drop
-- or a longer policy never moves an existing deadline later: that would hide
-- overdue work. The applier and the ingest upsert apply the rule; this
-- migration records every tightening on the finding's timeline, whatever
-- wrote it, as a sla_deadline_tightened activity with the old and new
-- deadline and, when the priority moved, the old and new class.
--
-- Live impact: a CHECK constraint rewrite on finding_activities (validated
-- in place, as in 002173) and one AFTER UPDATE trigger on findings.

-- Add the activity type to the existing CHECK list, whatever other
-- migrations added to it before this one ran: the list is read back from
-- the constraint and written again with the new value.
DO $$
DECLARE
    vals text[];
BEGIN
    SELECT array_agg(DISTINCT m[1]) INTO vals
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+)''', 'g') AS m
    WHERE c.conname = 'chk_activity_type' AND c.conrelid = 'finding_activities'::regclass;
    IF vals IS NOT NULL AND NOT 'sla_deadline_tightened' = ANY (vals) THEN
        ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
        EXECUTE format('ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (%s))',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM unnest(vals || 'sla_deadline_tightened'::text) AS v));
    END IF;
END;
$$;

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

COMMENT ON FUNCTION record_sla_deadline_tightened() IS
    'Row trigger: a timeline entry when an open finding''s SLA deadline moves earlier.';

DROP TRIGGER IF EXISTS trg_findings_sla_deadline_tightened ON findings;
CREATE TRIGGER trg_findings_sla_deadline_tightened
    AFTER UPDATE OF sla_deadline ON findings
    FOR EACH ROW
    WHEN (OLD.sla_deadline IS NOT NULL AND NEW.sla_deadline IS NOT NULL
          AND NEW.sla_deadline < OLD.sla_deadline
          AND is_open_finding_status(OLD.status) AND is_open_finding_status(NEW.status))
    EXECUTE FUNCTION record_sla_deadline_tightened();
