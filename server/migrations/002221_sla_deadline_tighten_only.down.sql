DROP TRIGGER IF EXISTS trg_findings_sla_deadline_tightened ON findings;
DROP FUNCTION IF EXISTS record_sla_deadline_tightened();
DELETE FROM finding_activities WHERE activity_type = 'sla_deadline_tightened';

DO $$
DECLARE
    vals text[];
BEGIN
    SELECT array_agg(DISTINCT m[1]) INTO vals
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+)''', 'g') AS m
    WHERE c.conname = 'chk_activity_type' AND c.conrelid = 'finding_activities'::regclass;
    IF vals IS NOT NULL AND 'sla_deadline_tightened' = ANY (vals) THEN
        ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
        EXECUTE format('ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (%s)) NOT VALID',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM unnest(array_remove(vals, 'sla_deadline_tightened')) AS v));
    END IF;
END;
$$;
