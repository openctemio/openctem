-- Finding timeline entry for remediation task membership
-- (docs/rfcs/RFC-098-remediation-tasks.md): a finding that joins, leaves or
-- moves between remediation tasks gets a remediation_task_changed activity
-- naming the task(s), the operation and the actor.
--
-- Live impact: the CHECK constraint on the large finding_activities table is
-- re-added NOT VALID (no full-table scan under the ACCESS EXCLUSIVE lock);
-- the migration remediation_task_activity_type_validate validates it.

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
    IF vals IS NOT NULL AND NOT 'remediation_task_changed' = ANY (vals) THEN
        ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
        EXECUTE format('ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (%s)) NOT VALID',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM unnest(vals || 'remediation_task_changed'::text) AS v));
    END IF;
END;
$$;
