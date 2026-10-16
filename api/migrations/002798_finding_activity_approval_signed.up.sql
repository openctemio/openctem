-- Finding timeline entry for one approval of a request that needs two
-- approvers (api/docs/rfcs/RFC-111-approval-policy.md): the first sign-off
-- is recorded as approval_signed; the last one is approval_approved.
--
-- Live impact: the CHECK constraint on the large finding_activities table is
-- re-added NOT VALID (no full-table scan under the ACCESS EXCLUSIVE lock);
-- the migration finding_activity_approval_signed_validate validates it.

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
    IF vals IS NOT NULL AND NOT 'approval_signed' = ANY (vals) THEN
        ALTER TABLE finding_activities DROP CONSTRAINT chk_activity_type;
        EXECUTE format('ALTER TABLE finding_activities ADD CONSTRAINT chk_activity_type CHECK (activity_type IN (%s)) NOT VALID',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM unnest(vals || 'approval_signed'::text) AS v));
    END IF;
END;
$$;
