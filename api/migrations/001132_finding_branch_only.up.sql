-- Branch-only findings (docs/architecture/branch-only-findings.md).
--
-- A finding seen only on branches that do not count as exposure (a feature
-- or merge-request branch) is marked branch_only. Exposure views (dashboards,
-- SLA, priority and CTEM metrics, notifications, the default findings list)
-- leave it out; the CI gate, the run and the branch pages still show it.
-- The mark is cleared when a counting branch sees the finding, and its SLA
-- clock starts then.
--
-- Live impact: one ADD COLUMN with a constant default (no table rewrite), a
-- partial index that holds only marked rows, three functions, two triggers
-- and a backfill over findings that have branch occurrences.

-- A branch counts as exposure when it is the repository's default branch, a
-- protected branch, a main or release branch by its detected type, or when
-- its repository has no known default branch yet (nothing is hidden until a
-- default branch is known). A branch that no longer exists counts (NULL is
-- treated as true by every caller), so nothing is hidden by mistake.
CREATE OR REPLACE FUNCTION branch_counts_as_exposure(p_branch_id UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE AS $$
    SELECT COALESCE((
        SELECT b.is_default OR b.is_protected OR b.branch_type IN ('main', 'release')
            OR NOT EXISTS (SELECT 1 FROM repository_branches d
                           WHERE d.repository_id = b.repository_id AND d.is_default)
        FROM repository_branches b WHERE b.id = p_branch_id
    ), TRUE)
$$;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS branch_only BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN findings.branch_only IS
    'Seen only on branches that do not count as exposure (branch_counts_as_exposure). Excluded from exposure views; cleared when a counting branch sees the finding.';

CREATE INDEX IF NOT EXISTS idx_findings_branch_only ON findings (tenant_id) WHERE branch_only;

-- A new finding first seen on a non-counting branch is branch-only. Only the
-- INSERT decides: a finding that already counts is never hidden later.
CREATE OR REPLACE FUNCTION findings_mark_branch_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.branch_only := NEW.branch_id IS NOT NULL AND NOT branch_counts_as_exposure(NEW.branch_id);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_findings_mark_branch_only ON findings;
CREATE TRIGGER trg_findings_mark_branch_only
    BEFORE INSERT ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_mark_branch_only();

-- promote_branch_only_findings clears the mark on the tenant's findings among
-- p_finding_ids that have an occurrence on a counting branch. The SLA clock
-- starts now: the deadline keeps its length, measured from now instead of
-- from first detection. first_detected_at keeps the first sighting on any
-- branch (the CI gate decides "new" from it); each branch's own first
-- sighting is in finding_branch_occurrences. Returns the promoted finding ids.
CREATE OR REPLACE FUNCTION promote_branch_only_findings(p_tenant_id UUID, p_finding_ids UUID[])
RETURNS SETOF UUID
LANGUAGE sql VOLATILE AS $$
    UPDATE findings f
    SET branch_only = FALSE,
        sla_deadline = f.sla_deadline + (NOW() - COALESCE(f.first_detected_at, f.created_at)),
        sla_status = CASE WHEN f.sla_deadline IS NULL THEN f.sla_status ELSE 'on_track' END,
        updated_at = NOW()
    WHERE f.tenant_id = p_tenant_id
      AND f.id = ANY(p_finding_ids)
      AND f.branch_only
      AND EXISTS (SELECT 1 FROM finding_branch_occurrences o
                  WHERE o.tenant_id = p_tenant_id AND o.finding_id = f.id
                    AND branch_counts_as_exposure(o.branch_id))
    RETURNING f.id
$$;

-- A branch that starts to count (made default, protected, or retyped to main
-- or release) promotes the branch-only findings seen on it.
CREATE OR REPLACE FUNCTION repository_branches_promote_branch_only() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    t RECORD;
BEGIN
    IF NOT branch_counts_as_exposure(NEW.id) THEN
        RETURN NULL;
    END IF;
    FOR t IN
        SELECT o.tenant_id, array_agg(o.finding_id) AS ids
        FROM finding_branch_occurrences o
        JOIN findings f ON f.id = o.finding_id AND f.tenant_id = o.tenant_id AND f.branch_only
        WHERE o.branch_id = NEW.id
        GROUP BY o.tenant_id
    LOOP
        PERFORM promote_branch_only_findings(t.tenant_id, t.ids);
    END LOOP;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_repository_branches_promote_branch_only ON repository_branches;
CREATE TRIGGER trg_repository_branches_promote_branch_only
    AFTER UPDATE OF is_default, is_protected, branch_type ON repository_branches
    FOR EACH ROW
    WHEN (NEW.is_default IS DISTINCT FROM OLD.is_default
       OR NEW.is_protected IS DISTINCT FROM OLD.is_protected
       OR NEW.branch_type IS DISTINCT FROM OLD.branch_type)
    EXECUTE FUNCTION repository_branches_promote_branch_only();

-- Backfill: findings whose every occurrence is on a non-counting branch.
UPDATE findings f
SET branch_only = TRUE
WHERE EXISTS (SELECT 1 FROM finding_branch_occurrences o WHERE o.finding_id = f.id AND o.tenant_id = f.tenant_id)
  AND NOT EXISTS (SELECT 1 FROM finding_branch_occurrences o
                  WHERE o.finding_id = f.id AND o.tenant_id = f.tenant_id
                    AND branch_counts_as_exposure(o.branch_id));
