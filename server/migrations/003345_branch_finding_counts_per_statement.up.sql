-- Branch finding counters, recounted once per statement instead of once per
-- row (docs/architecture/deduplication.md, "Branch counters").
--
-- update_branch_finding_counts() ran as a row trigger: every inserted,
-- deleted or moved finding on a branch ran five COUNT(*) over all of that
-- branch's findings and updated the branch row. A report of N findings on one
-- branch cost O(N^2) row reads (5,000 findings: 37.6 s, against 7.3 s without
-- the trigger) and held the branch row lock across the whole upload, which
-- serialised every upload of a repository.
--
-- The statement triggers below collect the distinct branches a statement
-- touched (transition tables) and recount each of them once, in one
-- aggregate pass, locking the branch rows in id order. The counts are the
-- same recount the row trigger made, so they stay exact (and self-heal a
-- counter that drifted). A statement trigger with transition tables cannot
-- be limited to columns, so the update trigger compares the old and new rows
-- itself: an update that moves no counted input (a re-sighting) recounts
-- nothing.
--
-- Live impact: replaces three triggers and one function on findings; no
-- data is rewritten. The counters stay correct through the switch (the
-- recount reads the table, not a delta).

-- DROP TRIGGER takes an ACCESS EXCLUSIVE lock on findings (no rewrite, held
-- for the length of this transaction only). Fail fast instead of queueing
-- every read of findings behind a long-running query.
SET LOCAL lock_timeout = '5s';

-- Recounts the given branches. Rows whose repository is gone (the cascade of
-- a tenant delete) are left alone, as before.
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
        LEFT JOIN findings f ON f.branch_id = b.id
        GROUP BY b.id
    ) c
    WHERE rb.id = c.id
      AND EXISTS (SELECT 1 FROM asset_repositories ar WHERE ar.asset_id = rb.repository_id);
END;
$$;
COMMENT ON FUNCTION refresh_branch_finding_counts(uuid[]) IS
    'Recounts the open findings (total and per severity) of the given repository branches, locking the branch rows in id order.';

-- Statement trigger over a findings transition table named changed_rows
-- (insert, delete).
CREATE OR REPLACE FUNCTION branch_finding_counts_from_rows() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM refresh_branch_finding_counts(ARRAY(
        SELECT DISTINCT r.branch_id FROM changed_rows r WHERE r.branch_id IS NOT NULL));
    RETURN NULL;
END;
$$;
COMMENT ON FUNCTION branch_finding_counts_from_rows() IS
    'Statement trigger: recounts the branches of the inserted or deleted findings once per statement.';

-- Statement trigger for findings updates over old_rows and new_rows: the old
-- and new branch of every finding whose branch, status or severity moved.
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

DROP TRIGGER IF EXISTS trg_update_branch_finding_counts_insert ON findings;
DROP TRIGGER IF EXISTS trg_update_branch_finding_counts_update ON findings;
DROP TRIGGER IF EXISTS trg_update_branch_finding_counts_delete ON findings;
DROP FUNCTION IF EXISTS update_branch_finding_counts();

CREATE TRIGGER trg_findings_branch_counts_insert
    AFTER INSERT ON findings
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION branch_finding_counts_from_rows();

CREATE TRIGGER trg_findings_branch_counts_delete
    AFTER DELETE ON findings
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION branch_finding_counts_from_rows();

CREATE TRIGGER trg_findings_branch_counts_update
    AFTER UPDATE ON findings
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION branch_finding_counts_from_update();
