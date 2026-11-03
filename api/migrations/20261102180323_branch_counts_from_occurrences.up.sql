-- Branch finding counters from the occurrence model (RFC-144 §4,
-- docs/architecture/branch-only-findings.md).
--
-- A finding is one row per identity key; the branches it is present on are
-- its rows in finding_branch_occurrences. The counters on repository_branches
-- still counted findings.branch_id, the one headline branch of a finding, so
-- a finding present on main and on feature/x counted only on main (ingest
-- moves branch_id to the default branch once the default branch sees it).
-- The branch page then disagreed with the findings list filtered on the same
-- branch, which reads occurrences.
--
-- A branch now counts a finding whose status is open when
--   * the finding has an open occurrence on the branch, or
--   * the finding has no occurrence at all and branch_id points at the branch
--     (rows written before occurrences existed keep counting where they did).
--
-- Occurrences are read through the branch's own repository tenant, so a row
-- linked to another tenant's branch can never move this tenant's counters.
--
-- Live impact: replaces two functions, adds three statement triggers on
-- finding_branch_occurrences, and recounts every branch once (one UPDATE of
-- repository_branches; findings are not rewritten).

SET LOCAL lock_timeout = '5s';

CREATE OR REPLACE FUNCTION refresh_branch_finding_counts(p_branch_ids uuid[]) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    IF p_branch_ids IS NULL OR cardinality(p_branch_ids) = 0 THEN
        RETURN;
    END IF;
    -- One lock order for every writer, so two uploads touching the same
    -- branches cannot deadlock on them.
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
        JOIN repository_branches br ON br.id = b.id
        JOIN assets a ON a.id = br.repository_id
        LEFT JOIN LATERAL (
            SELECT fo.id, fo.status, fo.severity
            FROM finding_branch_occurrences o
            JOIN findings fo ON fo.id = o.finding_id AND fo.tenant_id = o.tenant_id
            WHERE o.tenant_id = a.tenant_id AND o.branch_id = b.id AND o.status = 'open'
            UNION ALL
            SELECT fl.id, fl.status, fl.severity
            FROM findings fl
            WHERE fl.branch_id = b.id AND fl.tenant_id = a.tenant_id
              AND NOT EXISTS (SELECT 1 FROM finding_branch_occurrences x WHERE x.finding_id = fl.id)
        ) f ON true
        GROUP BY b.id
    ) c
    WHERE rb.id = c.id
      AND EXISTS (SELECT 1 FROM asset_repositories ar WHERE ar.asset_id = rb.repository_id);
END;
$$;
COMMENT ON FUNCTION refresh_branch_finding_counts(uuid[]) IS
    'Recounts the open findings (total and per severity) present on the given repository branches: an open occurrence on the branch, or branch_id for a finding with no occurrence. Locks the branch rows in id order.';

-- Findings updates: a branch, status or severity change moves the counters of
-- the old and new branch_id and of every branch the finding has an occurrence
-- on.
CREATE OR REPLACE FUNCTION branch_finding_counts_from_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM refresh_branch_finding_counts(ARRAY(
        WITH moved AS (
            SELECT n.id, n.tenant_id, n.branch_id AS new_branch, o.branch_id AS old_branch
            FROM new_rows n
            JOIN old_rows o ON o.id = n.id
            WHERE (o.status::text, o.severity::text, o.branch_id)
                  IS DISTINCT FROM (n.status::text, n.severity::text, n.branch_id)
        )
        SELECT m.new_branch FROM moved m WHERE m.new_branch IS NOT NULL
        UNION
        SELECT m.old_branch FROM moved m WHERE m.old_branch IS NOT NULL
        UNION
        SELECT occ.branch_id FROM moved m
        JOIN finding_branch_occurrences occ ON occ.finding_id = m.id AND occ.tenant_id = m.tenant_id));
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION branch_finding_counts_from_update() IS
    'Statement trigger: recounts the old and new branch and the occurrence branches of findings whose branch, status or severity changed, once per statement.';

-- Occurrence inserts and deletes (transition table changed_rows).
CREATE OR REPLACE FUNCTION branch_finding_counts_from_occurrences() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM refresh_branch_finding_counts(ARRAY(
        SELECT DISTINCT r.branch_id FROM changed_rows r WHERE r.branch_id IS NOT NULL));
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION branch_finding_counts_from_occurrences() IS
    'Statement trigger: recounts the branches of inserted or deleted finding occurrences once per statement.';

-- Occurrence updates: only a state or branch change moves a count (a
-- re-sighting that keeps the occurrence open recounts nothing).
CREATE OR REPLACE FUNCTION branch_finding_counts_from_occurrence_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM refresh_branch_finding_counts(ARRAY(
        SELECT DISTINCT x.branch_id
        FROM new_rows n
        JOIN old_rows o ON o.id = n.id
        CROSS JOIN LATERAL (VALUES (n.branch_id), (o.branch_id)) x(branch_id)
        WHERE x.branch_id IS NOT NULL
          AND (o.status, o.branch_id) IS DISTINCT FROM (n.status, n.branch_id)));
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION branch_finding_counts_from_occurrence_update() IS
    'Statement trigger: recounts the old and new branch of occurrences whose state or branch changed, once per statement.';

DROP TRIGGER IF EXISTS trg_fbo_branch_counts_insert ON finding_branch_occurrences;
DROP TRIGGER IF EXISTS trg_fbo_branch_counts_delete ON finding_branch_occurrences;
DROP TRIGGER IF EXISTS trg_fbo_branch_counts_update ON finding_branch_occurrences;

CREATE TRIGGER trg_fbo_branch_counts_insert
    AFTER INSERT ON finding_branch_occurrences
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION branch_finding_counts_from_occurrences();

CREATE TRIGGER trg_fbo_branch_counts_delete
    AFTER DELETE ON finding_branch_occurrences
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION branch_finding_counts_from_occurrences();

CREATE TRIGGER trg_fbo_branch_counts_update
    AFTER UPDATE ON finding_branch_occurrences
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION branch_finding_counts_from_occurrence_update();

-- Recount every branch once with the new rule.
SELECT refresh_branch_finding_counts(ARRAY(SELECT id FROM repository_branches));
