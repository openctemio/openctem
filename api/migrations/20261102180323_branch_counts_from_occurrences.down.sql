-- Restores the branch counters over findings.branch_id (migration 003345).

SET LOCAL lock_timeout = '5s';

DROP TRIGGER IF EXISTS trg_fbo_branch_counts_insert ON finding_branch_occurrences;
DROP TRIGGER IF EXISTS trg_fbo_branch_counts_delete ON finding_branch_occurrences;
DROP TRIGGER IF EXISTS trg_fbo_branch_counts_update ON finding_branch_occurrences;
DROP FUNCTION IF EXISTS branch_finding_counts_from_occurrences();
DROP FUNCTION IF EXISTS branch_finding_counts_from_occurrence_update();

CREATE OR REPLACE FUNCTION refresh_branch_finding_counts(p_branch_ids uuid[]) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF p_branch_ids IS NULL OR cardinality(p_branch_ids) = 0 THEN
        RETURN;
    END IF;
    PERFORM 1 FROM repository_branches rb
    WHERE rb.id = ANY(p_branch_ids)
    ORDER BY rb.id
    FOR NO KEY UPDATE;

    UPDATE repository_branches rb SET
        findings_total    = c.total,
        findings_critical = c.critical,
        findings_high     = c.high,
        findings_medium   = c.medium,
        findings_low      = c.low
    FROM (
        SELECT b.id,
               count(f.id) FILTER (WHERE is_open_finding_status(f.status))                            AS total,
               count(f.id) FILTER (WHERE f.severity = 'critical' AND is_open_finding_status(f.status)) AS critical,
               count(f.id) FILTER (WHERE f.severity = 'high' AND is_open_finding_status(f.status))     AS high,
               count(f.id) FILTER (WHERE f.severity = 'medium' AND is_open_finding_status(f.status))   AS medium,
               count(f.id) FILTER (WHERE f.severity = 'low' AND is_open_finding_status(f.status))      AS low
        FROM (SELECT DISTINCT unnest(p_branch_ids) AS id) b
        LEFT JOIN findings f ON f.branch_id = b.id
        GROUP BY b.id
    ) c
    WHERE rb.id = c.id
      AND EXISTS (SELECT 1 FROM asset_repositories ar WHERE ar.asset_id = rb.repository_id);
END;
$$;
COMMENT ON FUNCTION refresh_branch_finding_counts(uuid[]) IS
    'Recounts the open findings (total and per severity) of the given repository branches, locking the branch rows in id order.';

CREATE OR REPLACE FUNCTION branch_finding_counts_from_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM refresh_branch_finding_counts(ARRAY(
        SELECT DISTINCT x.branch_id
        FROM new_rows n
        JOIN old_rows o ON o.id = n.id
        CROSS JOIN LATERAL (VALUES (n.branch_id), (o.branch_id)) x(branch_id)
        WHERE x.branch_id IS NOT NULL
          AND (o.status::text, o.severity::text, o.branch_id)
              IS DISTINCT FROM (n.status::text, n.severity::text, n.branch_id)));
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION branch_finding_counts_from_update() IS
    'Statement trigger: recounts the old and new branches of findings whose branch, status or severity changed, once per statement.';

SELECT refresh_branch_finding_counts(ARRAY(SELECT id FROM repository_branches));
