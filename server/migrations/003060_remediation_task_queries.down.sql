-- Reverse remediation_task_queries: members that joined through a query
-- are recorded as manual joins, then 'query' leaves the join_source CHECK.
UPDATE remediation_task_members SET join_source = 'manual' WHERE join_source = 'query';

DO $$
DECLARE
    vals text[];
BEGIN
    SELECT array_agg(DISTINCT m[1]) INTO vals
    FROM pg_constraint c, regexp_matches(pg_get_constraintdef(c.oid), '''([a-z0-9_]+)''', 'g') AS m
    WHERE c.conname = 'chk_remediation_task_members_join_source' AND c.conrelid = 'remediation_task_members'::regclass;
    IF vals IS NOT NULL AND 'query' = ANY (vals) THEN
        ALTER TABLE remediation_task_members DROP CONSTRAINT chk_remediation_task_members_join_source;
        EXECUTE format('ALTER TABLE remediation_task_members ADD CONSTRAINT chk_remediation_task_members_join_source CHECK (join_source IN (%s))',
            (SELECT string_agg(quote_literal(v), ', ' ORDER BY v) FROM unnest(array_remove(vals, 'query')) AS v));
    END IF;
END;
$$;

DROP TABLE IF EXISTS remediation_task_queries;
