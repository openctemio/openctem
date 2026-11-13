-- Timeline entry type sla_rebaselined: the explicit, audited move of an open
-- compliance finding's deadline to its compliance window, counted from first
-- detection (docs/architecture/finding-practices.md). Only the
-- finding-practice command writes it, with -apply.
--
-- The CHECK is re-added NOT VALID here and validated in the next migration
-- (SHARE UPDATE EXCLUSIVE: reads and writes go on).
DO $$
DECLARE
    vals text[];
    added text[] := ARRAY['sla_rebaselined'];
BEGIN
    SELECT array_agg(DISTINCT m[1]) INTO vals
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+)''', 'g') AS m
    WHERE c.conname = 'chk_activity_type' AND c.conrelid = 'finding_activities'::regclass;
    IF vals IS NOT NULL AND NOT vals @> added THEN
        ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
        EXECUTE format('ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (%s)) NOT VALID',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM (SELECT DISTINCT unnest(vals || added) AS v) u));
    END IF;
END;
$$;
